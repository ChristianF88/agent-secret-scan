//! Unit tests. All values are invented and match no vendor format.

use std::sync::OnceLock;

use agentleaks_core::Route;

use super::*;

fn spec() -> &'static Spec {
    static S: OnceLock<Spec> = OnceLock::new();
    S.get_or_init(|| Spec::embedded().unwrap())
}

fn analyzer() -> &'static ShellAnalyzer<'static> {
    static A: OnceLock<ShellAnalyzer<'static>> = OnceLock::new();
    A.get_or_init(|| ShellAnalyzer::new(spec()).unwrap())
}

fn scan(text: &str) -> Vec<Candidate<'static>> {
    let mut out = Vec::new();
    analyzer().analyze(&Routed::raw_text(text, Route::Command), &mut out);
    for c in &out {
        assert!(
            text.get(c.span.clone()).is_some(),
            "bad span {:?} in {text:?}",
            c.span
        );
    }
    out
}

fn secrets(text: &str) -> Vec<String> {
    scan(text)
        .iter()
        .map(|c| c.secret.expose().to_owned())
        .collect()
}

/// Exactly one candidate, with this secret, at an exact span.
#[track_caller]
fn one(text: &str, secret: &str) -> Candidate<'static> {
    let out = scan(text);
    let got: Vec<_> = out.iter().map(|c| (c.rule_id, c.secret.expose())).collect();
    assert_eq!(out.len(), 1, "{text}: {got:?}");
    let c = out.into_iter().next().unwrap();
    assert_eq!(c.secret.expose(), secret, "{text}");
    assert_eq!(&text[c.span.clone()], secret, "span in {text}");
    c
}

/// Exactly one candidate, with this secret (span may be the enclosing word).
#[track_caller]
fn one_loose(text: &str, secret: &str) -> Candidate<'static> {
    let out = scan(text);
    let got: Vec<_> = out.iter().map(|c| (c.rule_id, c.secret.expose())).collect();
    assert_eq!(out.len(), 1, "{text}: {got:?}");
    let c = out.into_iter().next().unwrap();
    assert_eq!(c.secret.expose(), secret, "{text}");
    c
}

#[track_caller]
fn none(text: &str) {
    let got = secrets(text);
    assert!(got.is_empty(), "{text}: {got:?}");
}

// ---------------------------------------------------------------------
// Fixtures: fixtures/repo/.claude/settings.local.json (Bash(...) payloads)
// and fixtures/negatives/.claude/settings.local.json.
// ---------------------------------------------------------------------

const FIXTURE_POSITIVES: &[(&str, &str, &str, Category)] = &[
    (
        r#"PGPASSWORD=Tr0ub4dor-Kx9q psql -h 203.0.113.20 -U admin -d orders -c "select 1""#,
        "Tr0ub4dor-Kx9q",
        RULE_ENV_PREFIX,
        Category::EnvAssignment,
    ),
    (
        "sshpass -p 'Qw7!mZp2Lr' ssh deploy@203.0.113.41 'systemctl restart api'",
        "Qw7!mZp2Lr",
        RULE_CLI_ARG,
        Category::CliArgument,
    ),
    (
        r#"mysql -h 198.51.100.7 -u root -pHx82bLqv93 shop -e "show tables""#,
        "Hx82bLqv93",
        RULE_CLI_ARG,
        Category::CliArgument,
    ),
    (
        "redis-cli -h cache.acme.test -a R3d1sK3yV7pm ping",
        "R3d1sK3yV7pm",
        RULE_CLI_ARG,
        Category::CliArgument,
    ),
    (
        "docker login -u acme -p Dk9Lm2Qx7Wv4 registry.acme.test",
        "Dk9Lm2Qx7Wv4",
        RULE_CLI_ARG,
        Category::CliArgument,
    ),
    (
        "curl -u admin:Cu7lPw2026x https://api.acme.test/health",
        "Cu7lPw2026x",
        RULE_CLI_ARG,
        Category::CliArgument,
    ),
];

const FIXTURE_NEGATIVES: &[&str] = &[
    "npm test:*",
    "npm run:*",
    "PGPASSWORD=$PGPASSWORD psql -h db -U app",
    "docker run -p 8080:80 nginx",
    "mysql -u root -p shop",
    r#"curl -H "Authorization: Bearer ${TOKEN}" https://api.acme.test"#,
    "docker login -u ci --password-stdin registry.acme.test",
];

#[test]
fn fixture_positives() {
    for &(cmd, secret, rule, cat) in FIXTURE_POSITIVES {
        let c = one(cmd, secret);
        assert_eq!((c.rule_id, c.category), (rule, cat), "{cmd}");
        assert_eq!(c.confidence, Confidence::High, "{cmd}");
    }
}

#[test]
fn fixture_negatives() {
    for &cmd in FIXTURE_NEGATIVES {
        none(cmd);
        none(&cmd.replace('"', "\\\""));
    }
}

#[test]
fn context_host_user_and_severity() {
    let c = one(FIXTURE_POSITIVES[1].0, "Qw7!mZp2Lr");
    assert_eq!(c.context.tool.as_deref(), Some("sshpass"));
    assert_eq!(c.context.host.as_deref(), Some("203.0.113.41"));
    assert_eq!(c.context.user.as_deref(), Some("deploy"));
    assert_eq!(c.severity, Severity::Medium); // documentation range
    let c = one(FIXTURE_POSITIVES[0].0, "Tr0ub4dor-Kx9q");
    assert_eq!(c.context.tool.as_deref(), Some("psql"));
    assert_eq!(c.context.user.as_deref(), Some("admin"));
    let c = one("mysql -h db.acme.io -u app -pHx82bLqv93", "Hx82bLqv93");
    assert_eq!(c.severity, Severity::High);
    assert_eq!(c.context.host.as_deref(), Some("db.acme.io"));
    let c = one(
        "curl -u admin:Cu7lPw2026x https://api.acme.io/x",
        "Cu7lPw2026x",
    );
    assert_eq!(c.context.user.as_deref(), Some("admin"));
    assert_eq!(c.context.host.as_deref(), Some("api.acme.io"));
    // Default credentials are kept with low severity (D15).
    let c = one("keytool -list -storepass changeit", "changeit");
    assert_eq!(
        (c.kind, c.severity),
        (SecretKind::DefaultCredential, Severity::Low)
    );
}

// ---------------------------------------------------------------------
// Every ArgForm, at least three tools each.
// ---------------------------------------------------------------------

#[test]
fn arg_forms() {
    let table: &[(&str, &[(&str, &str)])] = &[
        (
            "attached",
            &[
                ("mysql -pHx82bLqv93 shop", "Hx82bLqv93"),
                ("7z x a.7z -pZq8wLk3v", "Zq8wLk3v"),
                ("rar x -hpRr5tQw9a a.rar", "Rr5tQw9a"),
                ("mariadb-dump -pMd4pQw8z db", "Md4pQw8z"),
            ],
        ),
        (
            "separate",
            &[
                ("redis-cli -a R3d1sK3yV7pm ping", "R3d1sK3yV7pm"),
                ("plink -pw Pl7nkPw3q deploy@h1", "Pl7nkPw3q"),
                (
                    "keytool -importcert -storepass Ks8tPw2x -file c",
                    "Ks8tPw2x",
                ),
                ("cqlsh -u cass -p Cq9lPw2x node1", "Cq9lPw2x"),
                ("ldapsearch -x -D cn=admin -w Ld4pPw9z -b dc=x", "Ld4pPw9z"),
            ],
        ),
        (
            "attached_or_separate",
            &[
                ("sshpass -pQw7mZp2Lr ssh h1", "Qw7mZp2Lr"),
                ("sshpass -p Qw7mZp2Lr ssh h1", "Qw7mZp2Lr"),
                ("smbclient //h1/share -U alice%Sm8bPw3x", "Sm8bPw3x"),
                ("sqlcmd -S db -U sa -PSq1Pw9xz", "Sq1Pw9xz"),
                ("curl -uadmin:Cu7lPw2026x https://x.io", "Cu7lPw2026x"),
            ],
        ),
        (
            "equals",
            &[
                ("mysql --password=My5qlPw9 db", "My5qlPw9"),
                ("aria2c --rpc-secret=Ar1aS3crx", "Ar1aS3crx"),
                ("wp core install --admin_password=Wp9adPw2", "Wp9adPw2"),
                (
                    "boundary authenticate password -password=Bd7rPw4x",
                    "Bd7rPw4x",
                ),
            ],
        ),
        (
            "equals_or_separate",
            &[
                ("mongosh --password Mg9oPw3x", "Mg9oPw3x"),
                ("mongosh --password=Mg9oPw3x", "Mg9oPw3x"),
                ("gpg --batch --passphrase Gp9gPhr4se -d f", "Gp9gPhr4se"),
                (
                    "kubectl get pods --token=Kt7oKenAbcd1234",
                    "Kt7oKenAbcd1234",
                ),
                ("snowsql -a acct --password Sn0wPw9x", "Sn0wPw9x"),
            ],
        ),
        (
            "colon",
            &[
                ("xfreerdp /u:admin /p:Rd9pPw3x /v:h1", "Rd9pPw3x"),
                ("cmdkey /generic:h1 /user:u /pass:Ck7yPw3x", "Ck7yPw3x"),
                (
                    "wmic /node:h1 /user:u /password:Wm1cPw7x os get",
                    "Wm1cPw7x",
                ),
                ("winrs -r:h1 -p:Wr5sPw9x dir", "Wr5sPw9x"),
            ],
        ),
        (
            "positional index",
            &[
                ("rabbitmqctl add_user bob Rb7tPw3x", "Rb7tPw3x"),
                ("wpa_passphrase homenet Wp4aPw9xx", "Wp4aPw9xx"),
                ("cargo login Cg9oTokenAbcdef12", "Cg9oTokenAbcdef12"),
                ("mosquitto_passwd -b pw.txt bob Mq7tPw3x", "Mq7tPw3x"),
                (
                    "mc alias set s3 https://s3.acme.io AKX12 Mc9SecretKeyAbc",
                    "Mc9SecretKeyAbc",
                ),
            ],
        ),
        (
            "positional last",
            &[
                ("htpasswd -b -c .htpasswd bob Ht7pPw3x", "Ht7pPw3x"),
                ("htpasswd -bc .htpasswd bob Ht7pPw3x", "Ht7pPw3x"),
                ("htpasswd -b .htpasswd alice Al1cePw9", "Al1cePw9"),
            ],
        ),
        (
            "positional any",
            &[
                ("psql 'host=db.acme.io password=Pq9sPw3x'", "Pq9sPw3x"),
                ("ovftool vm.ova vi://root:Ov7fPw3x@esx1.acme.io", "Ov7fPw3x"),
                (
                    "git clone https://bob:Gt7iPw3x@git.acme.io/r.git",
                    "Gt7iPw3x",
                ),
                ("heroku config:set DB_PASSWORD=Hk9rPw3x -a app", "Hk9rPw3x"),
                (
                    "http POST api.acme.io/x 'Authorization:Bearer Ht7pTokenAbcdef12'",
                    "Ht7pTokenAbcdef12",
                ),
            ],
        ),
    ];
    for (form, cases) in table {
        assert!(cases.len() >= 3, "{form}");
        for &(cmd, secret) in *cases {
            let c = one(cmd, secret);
            assert!(
                matches!(c.rule_id, RULE_CLI_ARG | RULE_KEYVALUE_ARG),
                "{form}: {cmd}: {}",
                c.rule_id
            );
        }
    }
}

#[test]
fn form_none_and_safe_flags() {
    for cmd in [
        "redis-cli --askpass -h h1",
        "docker login --password-stdin -u ci r.io",
        "openvpn --auth-user-pass creds.txt --config c.ovpn",
        "kinit --password-file=STDIN bob",
        "ldapsearch -W -D cn=admin",
        "plink -pwfile pw.txt h1",
        "gpg --passphrase-fd 0 -d f",
        "mongosh -p",
        "mongosh -p --host h1",
    ] {
        none(cmd);
    }
    // Passwords have no shape: a placeholder-looking password is reported.
    assert_eq!(
        secrets("curl -u admin:changeme https://x.io"),
        vec!["changeme"]
    );
}

// ---------------------------------------------------------------------
// ArgKinds
// ---------------------------------------------------------------------

#[test]
fn arg_kinds() {
    // password / passphrase / token / key
    assert_eq!(
        one("ssh-keygen -t ed25519 -N 'Sk9gPhr4se' -f k", "Sk9gPhr4se").kind,
        SecretKind::Passphrase
    );
    assert_eq!(
        one(
            "doctl compute list -t Dt9oTokenAbcdef12",
            "Dt9oTokenAbcdef12"
        )
        .kind,
        SecretKind::Token
    );
    assert_eq!(
        one(
            "dotnet nuget push p.nupkg -k Nk9eyAbcdefgh12",
            "Nk9eyAbcdefgh12"
        )
        .kind,
        SecretKind::Key
    );
    none("doctl compute list -t short"); // below the token minimum
    // userpass:<sep>
    one("lftp -u bob,Lf7tPw3x ftp.acme.io", "Lf7tPw3x");
    one("etcdctl --user root:Et9cPw3x get k", "Et9cPw3x");
    none("curl -u admin https://x.io"); // prompts for the password
    // prefixed:pass:
    one("openssl pkcs12 -in a.p12 -passin pass:Os9lPw3x", "Os9lPw3x");
    one(
        "apksigner sign --ks k.jks --ks-pass pass:Ap9kPw3x a.apk",
        "Ap9kPw3x",
    );
    none("openssl pkcs12 -in a.p12 -passin env:P12_PASS");
    none("openssl pkcs12 -in a.p12 -passin stdin");
    // keyvalue
    one("docker run -e PGPASSWORD=Dr9nPw3x postgres", "Dr9nPw3x");
    one("kcat -b k:9092 -X sasl.password=Kc9tPw3x -L", "Kc9tPw3x");
    one(
        "mount -t cifs //h/s /mnt -o user=bob,password=Mn7tPw3x,vers=3",
        "Mn7tPw3x",
    );
    one(
        "git -c 'http.extraHeader=Authorization: Basic Z2l0OkdpdDdQdzN4' clone https://git.acme.io/r",
        "Z2l0OkdpdDdQdzN4",
    );
    none("docker run -e LOG_LEVEL=debug -e PGPASSWORD=$PGPASSWORD postgres");
    // keyvalue_pair
    one(
        "aws configure set aws_secret_access_key Aw9sSecretKeyAbc",
        "Aw9sSecretKeyAbc",
    );
    one(
        "rclone config create r s3 provider AWS secret_access_key Rc9lSecretKeyAbc",
        "Rc9lSecretKeyAbc",
    );
    one(
        "npm config set //registry.acme.io/:_authToken=Np9mTokenAbcdef12",
        "Np9mTokenAbcdef12",
    );
    one(
        "git config http.extraheader 'AUTHORIZATION: bearer Gc9fTokenAbcdef12'",
        "Gc9fTokenAbcdef12",
    );
    none("aws configure set region eu-west-1");
    // header
    one(
        "curl -H 'Authorization: Bearer Cb9rTokenAbcdef12' https://x.io",
        "Cb9rTokenAbcdef12",
    );
    one(
        "wget --header='X-Api-Key: Wg9tKeyAbcdef1234' https://x.io",
        "Wg9tKeyAbcdef1234",
    );
    one(
        "grpcurl -H 'authorization: Basic Z3JwYzpHcjlQdw==' h:443 svc/M",
        "Z3JwYzpHcjlQdw==",
    );
    none("curl -H 'Content-Type: application/json' https://x.io");
    none("curl -H 'Authorization: Bearer $TOKEN' https://x.io");
    // header_or_item (httpie)
    one(
        "http POST x.io/login username=bob password=Hi9tPw3x",
        "Hi9tPw3x",
    );
    one("http x.io/q api_key==Hq9kKeyAbcdef12", "Hq9kKeyAbcdef12");
    none("http POST x.io/login username=bob Content-Type:application/json");
    // header_hashtable
    one(
        r#"Invoke-RestMethod -Uri https://x.io -Headers @{Authorization="Bearer Ir9mTokenAbcdef12"}"#,
        "Ir9mTokenAbcdef12",
    );
    // body
    one(
        "curl -d 'user=bob&password=Cd9bPw3x' https://x.io",
        "Cd9bPw3x",
    );
    one(
        r#"curl --data-raw '{"username":"bob","password":"Cj9sPw3x"}' https://x.io"#,
        "Cj9sPw3x",
    );
    none("curl -d 'q=search&page=2' https://x.io");
    // cookie
    one(
        "curl -b 'theme=dark; session_token=Ck9eTokenAbcdef12' https://x.io",
        "Ck9eTokenAbcdef12",
    );
    none("curl -b cookies.txt https://x.io");
}

#[test]
fn connect_syntaxes() {
    one(
        "redis-cli -u redis://default:Rd9sPw3x@cache.acme.io:6379",
        "Rd9sPw3x",
    );
    one(
        "psql -d 'postgresql://app:Pg9sPw3x@db.acme.io/x'",
        "Pg9sPw3x",
    );
    one(
        "pg_dump --dbname='host=db user=app password=Pd9mPw3x'",
        "Pd9mPw3x",
    );
    one(
        "beeline -u 'jdbc:hive2://h1:10000/db;user=bob;password=Bl9nPw3x'",
        "Bl9nPw3x",
    );
    one("sqlplus scott/T1ger9xq@orcl @script.sql", "T1ger9xq");
    none("sqlplus / as sysdba");
    none("sqlplus /nolog");
    one("secretsdump.py CORP/alice:Im9pPw3x@10.1.2.5", "Im9pPw3x");
    one(
        "cvs -d :pserver:bob:Cv9sPw3x@cvs.acme.io:/repo co m",
        "Cv9sPw3x",
    );
    one(
        "az storage blob list --connection-string 'DefaultEndpointsProtocol=https;AccountName=a;AccountKey=Az9kKeyAbcdefgh12=='",
        "Az9kKeyAbcdefgh12==",
    );
    one(
        "Invoke-Sqlcmd -Query 'select 1' -ConnectionString 'Server=db;User Id=sa;Password=Ad9oPw3x;'",
        "Ad9oPw3x",
    );
    one(
        "azcopy copy f 'https://a.blob.acme.io/c?sv=2022&sig=Sa9sSigAbcdef12'",
        "Sa9sSigAbcdef12",
    );
    let c = one(
        "mongosh --uri mongodb://app:Mo9nPw3x@db.acme.io/x",
        "Mo9nPw3x",
    );
    assert_eq!(c.context.user.as_deref(), Some("app"));
    assert_eq!(c.context.host.as_deref(), Some("db.acme.io"));
}

#[test]
fn patterns() {
    for (cmd, secret) in [
        (
            "db2 \"connect to sample user bob using Db2Pw9xq\"",
            "Db2Pw9xq",
        ),
        (
            "nmcli dev wifi connect homenet password Nm7cPw3x",
            "Nm7cPw3x",
        ),
        ("poetry config http-basic.acme bob Po9tPw3x", "Po9tPw3x"),
        ("bundle config set gems.acme.io bob:Bn9dPw3x", "Bn9dPw3x"),
        (
            "netsh wlan set hostednetwork ssid=x key=Ns9hPw3x",
            "Ns9hPw3x",
        ),
    ] {
        let c = one(cmd, secret);
        assert_eq!(c.rule_id, RULE_PATTERN, "{cmd}");
    }
    // Subcommand scoping applies to patterns too.
    none("poetry install http-basic.acme bob Po9tPw3x");
}

// ---------------------------------------------------------------------
// Tool lookup, subcommand scoping, special cases
// ---------------------------------------------------------------------

#[test]
fn tool_lookup() {
    for cmd in [
        "/usr/bin/mysql -pHx82bLqv93",
        "./mysql -pHx82bLqv93",
        "C:\\mysql\\bin\\mysql.exe -pHx82bLqv93",
        "MYSQL.EXE -pHx82bLqv93",
        "mariadb -pHx82bLqv93",
    ] {
        let c = one_loose(cmd, "Hx82bLqv93");
        assert_eq!(c.context.tool.as_deref(), Some("mysql"), "{cmd}");
    }
    // multi-word alias
    let c = one("clickhouse client --password Ch9kPw3x", "Ch9kPw3x");
    assert_eq!(c.context.tool.as_deref(), Some("clickhouse-client"));
    let c = one(
        "microk8s kubectl get pods --token=Mk8sTokenAbcd1234",
        "Mk8sTokenAbcd1234",
    );
    assert_eq!(c.context.tool.as_deref(), Some("kubectl"));
    // PowerShell cmdlets: case-insensitive flags
    one(
        "ConvertTo-SecureString -string 'Cv9tPw3x' -AsPlainText -Force",
        "Cv9tPw3x",
    );
    one(
        "ConvertTo-SecureString 'Cv9tPw3x' -AsPlainText -Force",
        "Cv9tPw3x",
    );
}

#[test]
fn subcommand_scoping() {
    none("docker run -p 8080:80 nginx");
    none("docker run -d -p 5432:5432 -p 80:80 postgres");
    one("docker login -p Dk9Lm2Qx7Wv4 r.io", "Dk9Lm2Qx7Wv4");
    one(
        "docker --context prod login -p Dk9Lm2Qx7Wv4 r.io",
        "Dk9Lm2Qx7Wv4",
    );
    one("podman login -u a -p Dk9Lm2Qx7Wv4 r.io", "Dk9Lm2Qx7Wv4");
    one("helm registry login r.io -u a -p Hr9gPw3x", "Hr9gPw3x");
    none("helm install x chart -p Hr9gPw3x");
    one(
        "kubectl -n prod create secret generic db --from-literal=password=Ku9bPw3x",
        "Ku9bPw3x",
    );
    one("gh secret set API_PASS -b Gh9sPw3x", "Gh9sPw3x");
    none("gh pr create -b Gh9sPw3x");
    one(
        "aws ssm put-parameter --name /x --value Aw9sPw3x --type SecureString",
        "Aw9sPw3x",
    );
    one(
        "aws --region eu-west-1 ssm put-parameter --name /x --value Aw9sPw3x",
        "Aw9sPw3x",
    );
    none("aws ec2 create-tags --value Aw9sPw3x");
    one(
        "security unlock-keychain -p Sc9kPw3x login.keychain",
        "Sc9kPw3x",
    );
}

#[test]
fn any_name_literals() {
    let out = scan(
        "kubectl create secret generic db --from-literal=username=bobby1 --from-literal=signing=Sg9nOpaque4x --from-literal=password=Ku9bPw3x",
    );
    let got: Vec<_> = out
        .iter()
        .map(|c| (c.secret.expose(), c.confidence))
        .collect();
    // Any key counts in a Secret, except the identity next to the
    // credential (`username`, `user`, `login`, `email`).
    assert_eq!(
        got,
        vec![
            ("Sg9nOpaque4x", Confidence::Medium),
            ("Ku9bPw3x", Confidence::High)
        ]
    );
    let got = secrets("vault kv put secret/app api=Vk9vValueAbc db_password=Vp9wPw3x");
    assert_eq!(got, vec!["Vk9vValueAbc", "Vp9wPw3x"]);
}

#[test]
fn mysql_special_cases() {
    none("mysql -p");
    none("mysql -p shop");
    none("mysql -u root -p shop");
    none("mysqldump -p --all-databases");
    one("mysql -u root -pHx82bLqv93 shop", "Hx82bLqv93");
}

// ---------------------------------------------------------------------
// Env prefixes
// ---------------------------------------------------------------------

#[test]
fn env_prefixes() {
    let c = one("PGPASSWORD=Tr0ub4dor-Kx9q psql -h db", "Tr0ub4dor-Kx9q");
    assert_eq!(c.category, Category::EnvAssignment);
    one("MYSQL_PWD='My9sPw3x' mysql -u root", "My9sPw3x");
    one("export DB_PASSWORD=\"Ex9pPw3x\"", "Ex9pPw3x");
    one("REDISCLI_AUTH=Rc9lPw3x", "Rc9lPw3x");
    // in the tool's `env:` list only
    one("SQLCMDPASSWORD=Sq9lPw3x sqlcmd -S db", "Sq9lPw3x");
    none("SQLCMDPASSWORD=Sq9lPw3x ls");
    one("ETCDCTL_USER=root:Et9cPw3x etcdctl get k", "Et9cPw3x");
    none("LANG=C PGPASSWORD=$PGPASSWORD psql");
    none("DB_PASSWORD_FILE=/run/secrets/db app");
    none("MAX_TOKENS=4096 run");
    none("PGPASSWORD=\"$(cat ~/.pgpw)\" psql");
}

// ---------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------

#[test]
fn passthrough_wrappers() {
    one("sudo -u postgres psql 'password=Su9dPw3x'", "Su9dPw3x");
    one("env PGPASSWORD=En7vPw3x psql", "En7vPw3x");
    one("op run --env-file=.env -- mysql -pOp9rPw3x", "Op9rPw3x");
    one("timeout 30 nice -n 5 mysql -pTn9tPw3x", "Tn9tPw3x");
    one("aws-vault exec prod -- mysql -pAv9xPw3x", "Av9xPw3x");
    one("watch -n 5 'mysql -pWa9tPw3x -e status'", "Wa9tPw3x");
    one("gdb --args mysql -pGd9bPw3x", "Gd9bPw3x");
    let got = secrets("sshpass -p 'Qw7!mZp2Lr' ssh deploy@h1 'mysql -pSp9iPw3x'");
    assert_eq!(got, vec!["Qw7!mZp2Lr", "Sp9iPw3x"]);
}

#[test]
fn string_arg_wrappers() {
    one("bash -c 'mysql -pBa9sPw3x'", "Ba9sPw3x");
    one("bash -lc \"mysql -pBl9cPw3x && echo ok\"", "Bl9cPw3x");
    one("sh -c 'PGPASSWORD=Sh9cPw3x psql'", "Sh9cPw3x");
    one("su - postgres -c 'psql \"password=Su9cPw3x\"'", "Su9cPw3x");
    one("ssh -p 2222 -i k deploy@h1 'mysql -pSs9hPw3x'", "Ss9hPw3x");
    one("ssh h1 mysql -pSs9hPw3x", "Ss9hPw3x");
    one(
        "powershell -Command \"ConvertTo-SecureString 'Pw9sPw3x' -AsPlainText -Force\"",
        "Pw9sPw3x",
    );
    one("pwsh.exe -c 'Invoke-Sqlcmd -Password Pw9sPw3x'", "Pw9sPw3x");
    one("cmd /c mysql -pCm9dPw3x", "Cm9dPw3x");
    one("eval \"mysql -pEv9aPw3x\"", "Ev9aPw3x");
    one("tmux send-keys -t s1 'mysql -pTm9xPw3x' Enter", "Tm9xPw3x");
    one("busybox sh -c 'mysql -pBb9xPw3x'", "Bb9xPw3x");
    // escaped inner string: span falls back to the whole argument
    let t = "bash -c \"mysql -p\\\"Bq9xPw3x\\\"\"";
    let c = one_loose(t, "Bq9xPw3x");
    assert_eq!(&t[c.span.clone()], "\"mysql -p\\\"Bq9xPw3x\\\"\"");
}

#[test]
fn double_dash_and_container_wrappers() {
    one("kubectl exec -it db-0 -- mysql -pKe9xPw3x", "Ke9xPw3x");
    one(
        "kubectl -n prod exec db-0 -- env PGPASSWORD=Ke9xPw3x psql",
        "Ke9xPw3x",
    );
    one("oc exec db-0 -- mysql -pOc9xPw3x", "Oc9xPw3x");
    one("docker exec -it -u root db mysql -pDe9xPw3x", "De9xPw3x");
    one(
        "docker run --rm -it --network host mysql:8 mysql -h db -pDr9nPw3x",
        "Dr9nPw3x",
    );
    one("docker compose exec db mysql -pDc9xPw3x", "Dc9xPw3x");
    one("vagrant ssh -c 'mysql -pVg9tPw3x'", "Vg9tPw3x");
    one(
        "gcloud compute ssh vm1 --command='mysql -pGc9lPw3x'",
        "Gc9lPw3x",
    );
    one(
        "aws ssm send-command --document-name AWS-RunShellScript --parameters 'commands=[\"mysql -pAs9mPw3x\"]'",
        "As9mPw3x",
    );
    // outer KB args and inner command together
    let got = secrets("docker exec -e PGPASSWORD=Dx9ePw3x db psql 'password=Dx9iPw3x'");
    assert_eq!(got.len(), 2, "{got:?}");
}

#[test]
fn depth_limit() {
    one("sudo sudo sudo sudo mysql -pDp9tPw3x", "Dp9tPw3x");
    none("sudo sudo sudo sudo sudo mysql -pDp9tPw3x");
    one("bash -c \"sh -c 'mysql -pNs9tPw3x'\"", "Ns9tPw3x");
}

// ---------------------------------------------------------------------
// keyvalue_arg_tools
// ---------------------------------------------------------------------

#[test]
fn keyvalue_arg_tools() {
    one(
        "helm install x c --set db.password=He9lPw3x,db.user=app",
        "He9lPw3x",
    );
    one(
        "helm upgrade x c --set-string auth.rootPassword=He9sPw3x",
        "He9sPw3x",
    );
    one("terraform apply -var 'db_password=Tf9rPw3x'", "Tf9rPw3x");
    one("terraform apply -var=db_password=Tf9rPw3x", "Tf9rPw3x");
    one("make deploy DB_PASSWORD=Mk9ePw3x", "Mk9ePw3x");
    one(
        "ansible-playbook site.yml -e 'ansible_become_pass=An9sPw3x env=prod'",
        "An9sPw3x",
    );
    one(
        "mvn spring-boot:run -Dspring.datasource.password=Mv9nPw3x",
        "Mv9nPw3x",
    );
    one("dotnet run -- --Database:Password=Dn9tPw3x", "Dn9tPw3x");
    one(
        "docker build --build-arg NPM_TOKEN=Db9aTokenAbcdef12 .",
        "Db9aTokenAbcdef12",
    );
    none("make build VERBOSE=1");
    none("helm install x c --set replicas=3");
    let c = one("make deploy DB_PASSWORD=Mk9ePw3x", "Mk9ePw3x");
    assert_eq!(c.rule_id, RULE_KEYVALUE_ARG);
}

// ---------------------------------------------------------------------
// stdin pipelines
// ---------------------------------------------------------------------

#[test]
fn stdin_pipelines() {
    let c = one(
        "echo 'Dk9Lm2Qx7Wv4' | docker login -u a --password-stdin r.io",
        "Dk9Lm2Qx7Wv4",
    );
    assert_eq!(
        (c.rule_id, c.category),
        (RULE_STDIN_PIPE, Category::CliStdin)
    );
    assert_eq!(c.context.tool.as_deref(), Some("docker"));
    one(
        "echo -n Dk9Lm2Qx7Wv4 | podman login --password-stdin -u a r.io",
        "Dk9Lm2Qx7Wv4",
    );
    one("echo 'bob:Ch9pPw3x' | chpasswd", "Ch9pPw3x");
    one(
        "printf '%s\\n' 'Pf9rPw3x' | sudo -S apt-get update",
        "Pf9rPw3x",
    );
    one("printf 'Pf9rPw3x\\n' | sudo -kS true", "Pf9rPw3x");
    one(
        "docker login --password-stdin -u a r.io <<< 'Hs9tPw3x'",
        "Hs9tPw3x",
    );
    one(
        "cat <<< Hs9tPw3x | docker login --password-stdin r.io",
        "Hs9tPw3x",
    );
    one(
        "cat <<EOF | docker login --password-stdin r.io\nHd9cPw3x\nEOF",
        "Hd9cPw3x",
    );
    one(
        "echo 'Gh9aTokenAbcdef12' | gh auth login --with-token",
        "Gh9aTokenAbcdef12",
    );
    one(
        "echo Vt9lTokenAbcdef12 | vault login -",
        "Vt9lTokenAbcdef12",
    );
    one("echo Kn9tPw3x | kinit bob@ACME.IO", "Kn9tPw3x");
    none("echo $TOKEN | gh auth login --with-token");
    none("echo 'select 1' | psql -h db");
    none("echo hello | docker login r.io"); // no --password-stdin: not a sink
    none("echo 'Dk9Lm2Qx7Wv4' ; docker login --password-stdin r.io"); // not piped
}

// ---------------------------------------------------------------------
// Input forms
// ---------------------------------------------------------------------

#[test]
fn glob_suffixes() {
    one("curl -u admin:Cu7lPw2026x:*", "Cu7lPw2026x");
    one("mysql -pHx82bLqv93 *", "Hx82bLqv93");
}

#[test]
fn multi_line_and_operators() {
    let t = "cd /srv && mysql -pMl9tPw3x < dump.sql\nredis-cli -a Ml9rPw3xAbc ping || true";
    assert_eq!(secrets(t), vec!["Ml9tPw3x", "Ml9rPw3xAbc"]);
    let t = "(cd app; PGPASSWORD=Sb9sPw3x psql) & wait";
    assert_eq!(secrets(t), vec!["Sb9sPw3x"]);
    let t = "if true; then mysql -pIf9tPw3x; fi";
    assert_eq!(secrets(t), vec!["If9tPw3x"]);
}

#[test]
fn placeholders_and_references() {
    for cmd in [
        "mysql -p$MYSQL_PASSWORD",
        "mysql -p\"${DB_PASS}\"",
        "sshpass -p \"$(cat pw)\" ssh h",
        "docker login -p '<password>' r.io",
        "redis-cli -a '***' ping",
        "psql 'password={{ .Values.pw }}'",
    ] {
        none(cmd);
    }
}

#[test]
fn rule_ids_are_documented_constants() {
    for id in [
        RULE_ENV_PREFIX,
        RULE_CLI_ARG,
        RULE_PATTERN,
        RULE_KEYVALUE_ARG,
        RULE_STDIN_PIPE,
    ] {
        assert!(id.starts_with("shell."));
    }
}

// ---------------------------------------------------------------------
// Review regressions (one test per finding)
// ---------------------------------------------------------------------

#[test]
fn subshell_paren_is_not_part_of_the_secret() {
    let c = one(
        "(cd /app && sqlcmd -S s -U sa -P Hx7Qw2Lm9Tz)",
        "Hx7Qw2Lm9Tz",
    );
    assert_eq!(c.context.tool.as_deref(), Some("sqlcmd"));
    one("(mysql -pHx7Qw2Lm9Tz) && echo ok", "Hx7Qw2Lm9Tz");
    one("( (sshpass -p Hx7Qw2Lm9Tz ssh h) )", "Hx7Qw2Lm9Tz");
    // A quoted `)` stays in the value.
    one("(mysql '-pHx7Qw2Lm9Tz)')", "Hx7Qw2Lm9Tz)");
}

#[test]
fn input_is_not_json_decoded() {
    // `\n` is not a newline in raw shell text.
    one(
        "sqlcmd -S db01\\nightly -U sa -P Hx7Qw2Lm9Tz",
        "Hx7Qw2Lm9Tz",
    );
    // `\\` inside single quotes is two backslashes.
    one("sshpass -p 'Ab\\\\9xQwLm' ssh h", "Ab\\\\9xQwLm");
    // Extractor output is already decoded: a backslash stays one backslash.
    one("mysql '-pJe9s\\Pw3x'", "Je9s\\Pw3x");
}

#[test]
fn stdin_sinks_behind_wrappers() {
    let c = one("echo 'root:Hx7Qw2Lm9Tz' | sudo chpasswd", "Hx7Qw2Lm9Tz");
    assert_eq!(c.rule_id, RULE_STDIN_PIPE);
    let c = one(
        "echo Hx7Qw2Lm9Tz | sudo docker login -u b --password-stdin",
        "Hx7Qw2Lm9Tz",
    );
    assert_eq!(c.context.tool.as_deref(), Some("docker"));
    one(
        "echo 'root:Hx7Qw2Lm9Tz' | sudo -u root env LANG=C chpasswd",
        "Hx7Qw2Lm9Tz",
    );
    one("printf 'Hx7Qw2Lm9Tz' | sudo -S true", "Hx7Qw2Lm9Tz");
    none("echo $PW | sudo docker login -u b --password-stdin");
    none("echo 'select 1' | sudo psql");
    none("echo hello | sudo docker login r.io");
}

#[test]
fn passthrough_wrapper_keeps_its_own_flag_values() {
    for cmd in [
        "sshpass -p Hx7Qw2Lm9Tz scp f u@h:/tmp",
        "sshpass -p Hx7Qw2Lm9Tz sftp u@h",
        "sshpass -p Hx7Qw2Lm9Tz rsync -a f u@h:/tmp",
        "sshpass -pHx7Qw2Lm9Tz scp f u@h:/tmp",
    ] {
        let c = one(cmd, "Hx7Qw2Lm9Tz");
        assert_eq!(c.context.tool.as_deref(), Some("sshpass"), "{cmd}");
    }
    // The inner command is still analyzed after the wrapper's values.
    one("sudo -u postgres mysql -pHx7Qw2Lm9Tz", "Hx7Qw2Lm9Tz");
    none("sshpass -f pwfile scp f u@h:/tmp");
}

#[test]
fn subcommand_words_with_flags_between() {
    one(
        "kubectl --context prod -n x create secret docker-registry r --docker-password=Hx7Qw2Lm9Tz",
        "Hx7Qw2Lm9Tz",
    );
    one(
        "kubectl create -n x secret generic s --from-literal=password=Hx7Qw2Lm9Tz",
        "Hx7Qw2Lm9Tz",
    );
    // A non-flag word that is not a flag value breaks the subcommand.
    none("kubectl create configmap secret --from-literal=password=Hx7Qw2Lm9Tz");
    none("docker run -p 8080:80 nginx");
    none("docker --context prod run -d -p 8080:80 nginx");
}

#[test]
fn any_name_mode_falls_back_to_credential() {
    let c = one("vault kv put secret/app apikey=Hx7Qw2Lm9Tz", "Hx7Qw2Lm9Tz");
    assert_eq!(c.kind, SecretKind::Credential);
    // Without `names: any` the key minimum still applies.
    none("helm install x c --set apikey=Hx7Qw2Lm9Tz");
}

#[test]
fn catalogue_gaps() {
    one(
        "mongosh \"mongodb://adm:Hx7Qw2Lm9Tz@mongo/db\"",
        "Hx7Qw2Lm9Tz",
    );
    none("mongosh \"mongodb://mongo/db\"");
    one("ldapsearch -x -wHx7Qw2Lm9Tz", "Hx7Qw2Lm9Tz");
    one("ldapsearch -x -w Hx7Qw2Lm9Tz", "Hx7Qw2Lm9Tz");
    none("ldapsearch -x -W");
    one(
        "curl -H\"Authorization: Bearer opaqueTok3nValue9\" https://x.io",
        "opaqueTok3nValue9",
    );
}

#[test]
fn no_false_positives_on_ports_and_references() {
    for cmd in [
        "docker run -p 8080:80 nginx",
        "mysql -p db",
        "ssh -p 2222 deploy@h1",
        "scp -P 2222 f h:/x",
        "git -c core.sshCommand='ssh -p 2222' fetch",
        "docker login -u ci --password-stdin r.io",
        "mysql -p$DB_PASSWORD",
        "mysql -p${DB_PASSWORD}",
        "sshpass -p \"$(cat pw)\" scp f h:/x",
        "(cd /app && sqlcmd -S s -U sa -P $SA_PASSWORD)",
    ] {
        none(cmd);
    }
}

#[test]
fn debug_output_redacts_raw_text() {
    let c = Cred::bare("Hx7Qw2Lm9Tz");
    let d = format!("{c:?}");
    assert!(!d.contains("Hx7Qw2Lm9Tz"), "{d}");
    let mut sc = Scratch::default();
    let mut out = Vec::new();
    analyzer().run("mysql -pHx7Qw2Lm9Tz", &mut sc, &mut out);
    let d = format!("{sc:?}");
    assert!(!d.contains("Hx7Qw2Lm9Tz"), "{d}");
}
