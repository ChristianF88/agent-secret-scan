//! Generator templates: realistic commands, config lines and prose that AI
//! coding agents write, with a `{S}` slot for the secret (positives) or no
//! secret at all (negatives). All hosts, users and values are invented.
//!
//! Slots: `{S}` secret, shell-quoted when needed; `{s}` secret inserted raw
//! (the template already quotes it); `{H}` host; `{U}` user; `{DB}`
//! database name; `{N}` a short resource name.

/// Value domain of a slot: decides which value styles fit and how the label
/// is judged (placeholders are optional for passwords, D60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K {
    Pw,
    /// Password inside a URI or `user/pass@db`: no `@:/?#%` characters.
    UriPw,
    Tok,
    Key,
}

/// How the secret is passed, which fixes the expected category and rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// A `cli_tools` flag or positional argument.
    Arg,
    /// `NAME=value` env prefix or `export`.
    Env,
    /// Piped into a stdin sink.
    Stdin,
    /// `NAME=VAL` argument (`keyvalue` args and `keyvalue_arg_tools`).
    KeyValue,
    /// Credential inside a URI / connect string argument.
    Connect,
}

impl How {
    pub fn category(self) -> &'static str {
        match self {
            Env => "env_assignment",
            Stdin => "cli_stdin",
            Arg | KeyValue | Connect => "cli_argument",
        }
    }
    pub fn rule(self) -> Option<&'static str> {
        match self {
            Arg => Some("shell.cli-arg"),
            Env => Some("shell.env-prefix"),
            Stdin => Some("shell.stdin-pipe"),
            KeyValue | Connect => None,
        }
    }
}

use How::*;
use K::*;

/// Commands that carry a credential: (id, template, value domain, how).
pub const POS_COMMANDS: &[(&str, &str, K, How)] = &[
    // ---- databases ----
    (
        "mysql.attached",
        "mysql -h {H} -u {U} -p{S} {DB} -e \"show tables\"",
        Pw,
        Arg,
    ),
    (
        "mysqldump.equals",
        "mysqldump -u {U} --password={S} {DB} > /tmp/{DB}.sql",
        Pw,
        Arg,
    ),
    ("mariadb.attached", "mariadb -u {U} -p{S} -h {H}", Pw, Arg),
    (
        "mysqladmin.attached",
        "mysqladmin -u root -p{S} status",
        Pw,
        Arg,
    ),
    (
        "mysql.env",
        "MYSQL_PWD={S} mysql -u {U} -h {H} {DB}",
        Pw,
        Env,
    ),
    (
        "psql.env",
        "PGPASSWORD={S} psql -h {H} -U {U} -d {DB} -c \"select 1\"",
        Pw,
        Env,
    ),
    (
        "psql.conninfo",
        "psql \"host={H} user={U} password={s} dbname={DB}\"",
        UriPw,
        Connect,
    ),
    (
        "psql.uri",
        "psql postgresql://{U}:{s}@{H}:5432/{DB}",
        UriPw,
        Connect,
    ),
    (
        "pg_dump.uri",
        "pg_dump \"postgres://{U}:{s}@{H}/{DB}\" -Fc -f backup.dump",
        UriPw,
        Connect,
    ),
    (
        "sqlcmd.separate",
        "sqlcmd -S {H} -U sa -P {S} -Q \"SELECT 1\"",
        Pw,
        Arg,
    ),
    (
        "sqlplus.userpass",
        "sqlplus {U}/{s}@{H}:1521/ORCL",
        UriPw,
        Connect,
    ),
    (
        "clickhouse.separate",
        "clickhouse-client --host {H} --user {U} --password {S} --query \"select 1\"",
        Pw,
        Arg,
    ),
    ("cqlsh.separate", "cqlsh {H} -u cassandra -p {S}", Pw, Arg),
    (
        "cypher-shell.separate",
        "cypher-shell -a bolt://{H}:7687 -u neo4j -p {S}",
        Pw,
        Arg,
    ),
    ("redis-cli.a", "redis-cli -h {H} -a {S} ping", Pw, Arg),
    (
        "redis-cli.uri",
        "redis-cli -u redis://default:{s}@{H}:6379 info",
        UriPw,
        Connect,
    ),
    (
        "redis-cli.env",
        "REDISCLI_AUTH={S} redis-cli -h {H} --scan",
        Pw,
        Env,
    ),
    (
        "mongosh.uri",
        "mongosh \"mongodb://{U}:{s}@{H}:27017/{DB}?authSource=admin\"",
        UriPw,
        Connect,
    ),
    (
        "mongodump.uri",
        "mongodump --uri=\"mongodb+srv://{U}:{s}@{H}/{DB}\" --out ./dump",
        UriPw,
        Connect,
    ),
    (
        "mongosh.p",
        "mongosh --host {H} -u {U} -p {S} --authenticationDatabase admin",
        Pw,
        Arg,
    ),
    (
        "influx.v1",
        "influx -username admin -password {S} -execute 'SHOW DATABASES'",
        Pw,
        Arg,
    ),
    (
        "influx.token",
        "influx bucket list --host https://{H}:8086 --token {S}",
        Tok,
        Arg,
    ),
    (
        "etcdctl.password",
        "etcdctl --endpoints https://{H}:2379 --user root --password {S} get /config",
        Pw,
        Arg,
    ),
    (
        "rabbitmqctl.add_user",
        "rabbitmqctl add_user {U} {S}",
        Pw,
        Arg,
    ),
    (
        "rabbitmqadmin.p",
        "rabbitmqadmin -H {H} -u admin -p {S} list queues",
        Pw,
        Arg,
    ),
    (
        "kcat.sasl",
        "kcat -b {H}:9093 -X security.protocol=SASL_SSL -X sasl.username={U} -X sasl.password={S} -L",
        Pw,
        KeyValue,
    ),
    (
        "mosquitto_pub.P",
        "mosquitto_pub -h {H} -u {U} -P {S} -t sensors/temp -m 21",
        Pw,
        Arg,
    ),
    (
        "nats.password",
        "nats pub --server nats://{H}:4222 --user {U} --password {S} orders.new hello",
        Pw,
        Arg,
    ),
    (
        "snowsql.password",
        "snowsql -a acme-eu -u {U} --password {S} -q 'select 1'",
        Pw,
        Arg,
    ),
    // ---- remote access ----
    ("sshpass.p", "sshpass -p {S} ssh {U}@{H} 'uptime'", Pw, Arg),
    (
        "sshpass.attached",
        "sshpass -p{S} scp ./build.tgz {U}@{H}:/tmp/",
        Pw,
        Arg,
    ),
    (
        "sshpass.env",
        "SSHPASS={S} sshpass -e ssh {U}@{H} 'df -h'",
        Pw,
        Env,
    ),
    (
        "xfreerdp.p",
        "xfreerdp /v:{H} /u:{U} /p:{S} /cert:ignore",
        Pw,
        Arg,
    ),
    (
        "smbclient.U",
        "smbclient //{H}/share -U {U}%{S} -c 'ls'",
        Pw,
        Arg,
    ),
    (
        "mount.cifs",
        "sudo mount -t cifs //{H}/data /mnt/data -o username={U},password={S},vers=3.0",
        Pw,
        KeyValue,
    ),
    ("lftp.u", "lftp -u {U},{S} sftp://{H}", Pw, Arg),
    ("plink.pw", "plink -ssh {U}@{H} -pw {S} \"df -h\"", Pw, Arg),
    (
        "ipmitool.P",
        "ipmitool -I lanplus -H {H} -U ADMIN -P {S} chassis status",
        Pw,
        Arg,
    ),
    (
        "ldapsearch.w",
        "ldapsearch -x -H ldap://{H} -D \"cn=admin,dc=acme,dc=test\" -w {S} -b \"dc=acme,dc=test\"",
        Pw,
        Arg,
    ),
    (
        "openstack.os-password",
        "openstack --os-username {U} --os-password {S} server list",
        Pw,
        Arg,
    ),
    (
        "evil-winrm.p",
        "evil-winrm -i {H} -u Administrator -p {S}",
        Pw,
        Arg,
    ),
    ("nxc.p", "nxc smb {H} -u {U} -p {S} --shares", Pw, Arg),
    ("winrs.p", "winrs -r:{H} -u:{U} -p:{S} ipconfig", Pw, Arg),
    (
        "vncviewer.passwd",
        "x11vnc -display :0 -passwd {S} -forever",
        Pw,
        Arg,
    ),
    // ---- HTTP ----
    ("curl.u", "curl -u {U}:{S} https://{H}/api/health", Pw, Arg),
    (
        "curl.bearer",
        "curl -sS -H \"Authorization: Bearer {s}\" https://{H}/v1/me",
        Tok,
        Arg,
    ),
    (
        "curl.user-quoted",
        "curl --user \"{U}:{s}\" https://{H}/",
        Pw,
        Arg,
    ),
    (
        "curl.x-api-key",
        "curl -H \"X-Api-Key: {s}\" https://{H}/v2/items",
        Tok,
        Arg,
    ),
    (
        "curl.form-secret",
        "curl -X POST https://{H}/oauth/token -d \"grant_type=client_credentials&client_id=app&client_secret={s}\"",
        Tok,
        Arg,
    ),
    (
        "curl.json-password",
        "curl -X POST https://{H}/login -H 'Content-Type: application/json' -d '{\"username\":\"{U}\",\"password\":\"{s}\"}'",
        Pw,
        Arg,
    ),
    (
        "curl.oauth2-bearer",
        "curl --oauth2-bearer {S} https://{H}/api",
        Tok,
        Arg,
    ),
    (
        "curl.cookie",
        "curl -b \"theme=dark; auth_token={s}\" https://{H}/",
        Tok,
        Arg,
    ),
    (
        "wget.password",
        "wget --user={U} --password={S} https://{H}/artifact.tgz",
        Pw,
        Arg,
    ),
    (
        "wget.header",
        "wget --header=\"Authorization: Token {s}\" https://{H}/file",
        Tok,
        Arg,
    ),
    (
        "httpie.auth",
        "http -a {U}:{S} GET https://{H}/api/status",
        Pw,
        Arg,
    ),
    (
        "httpie.item",
        "http POST https://{H}/api/login username={U} password={S}",
        Pw,
        Arg,
    ),
    (
        "xh.header",
        "xh https://{H}/api Authorization:\"Bearer {s}\"",
        Tok,
        Arg,
    ),
    (
        "grpcurl.H",
        "grpcurl -H \"authorization: Bearer {s}\" {H}:443 list",
        Tok,
        Arg,
    ),
    // ---- VCS ----
    (
        "git.clone-uri",
        "git clone https://{U}:{s}@{H}/acme/app.git",
        UriPw,
        Connect,
    ),
    (
        "git.remote-uri",
        "git remote set-url origin https://oauth2:{s}@{H}/group/repo.git",
        UriPw,
        Connect,
    ),
    (
        "git.extraheader",
        "git -c http.extraHeader=\"Authorization: Basic {s}\" fetch origin",
        Tok,
        KeyValue,
    ),
    (
        "svn.password",
        "svn checkout https://{H}/svn/trunk --username {U} --password {S}",
        Pw,
        Arg,
    ),
    (
        "glab.token",
        "glab auth login --hostname {H} --token {S}",
        Tok,
        Arg,
    ),
    (
        "gh.secret-body",
        "gh secret set DB_PASSWORD --body {S}",
        Pw,
        Arg,
    ),
    (
        "glab.variable",
        "glab variable set DEPLOY_TOKEN {S}",
        Tok,
        Arg,
    ),
    // ---- containers ----
    ("docker.login-p", "docker login -u {U} -p {S} {H}", Pw, Arg),
    (
        "docker.login-equals",
        "docker login {H} --username {U} --password={S}",
        Pw,
        Arg,
    ),
    (
        "docker.login-stdin",
        "echo {S} | docker login -u {U} --password-stdin {H}",
        Pw,
        Stdin,
    ),
    (
        "podman.login-printf",
        "printf '%s' {S} | podman login --username {U} --password-stdin {H}",
        Pw,
        Stdin,
    ),
    (
        "docker.run-e",
        "docker run -e POSTGRES_PASSWORD={S} -p 5432:5432 postgres:16",
        Pw,
        KeyValue,
    ),
    (
        "docker.run-env",
        "docker run --rm -e DB_PASSWORD={S} -e LOG_LEVEL=debug acme/api:latest",
        Pw,
        KeyValue,
    ),
    (
        "docker.build-arg",
        "docker build --build-arg NPM_TOKEN={S} -t acme/web .",
        Tok,
        KeyValue,
    ),
    (
        "skopeo.creds",
        "skopeo copy --src-creds {U}:{S} docker://{H}/app:1 docker://registry.local/app:1",
        Pw,
        Arg,
    ),
    (
        "helm.repo-add",
        "helm repo add acme https://{H}/charts --username {U} --password {S}",
        Pw,
        Arg,
    ),
    (
        "helm.set",
        "helm upgrade --install api ./chart --set db.password={S} --set image.tag=1.4.2",
        Pw,
        KeyValue,
    ),
    (
        "helm.registry",
        "helm registry login {H} -u {U} -p {S}",
        Pw,
        Arg,
    ),
    (
        "kubectl.from-literal",
        "kubectl create secret generic db-creds --from-literal=username={U} --from-literal=password={S}",
        Pw,
        KeyValue,
    ),
    (
        "kubectl.docker-password",
        "kubectl create secret docker-registry regcred --docker-server={H} --docker-username={U} --docker-password={S}",
        Pw,
        Arg,
    ),
    (
        "kubectl.set-credentials",
        "kubectl config set-credentials ci --token={S}",
        Tok,
        Arg,
    ),
    (
        "oc.login",
        "oc login https://{H}:6443 -u {U} -p {S}",
        Pw,
        Arg,
    ),
    (
        "argocd.login",
        "argocd login {H} --username admin --password {S}",
        Pw,
        Arg,
    ),
    ("crane.login", "crane auth login {H} -u {U} -p {S}", Pw, Arg),
    // ---- cloud ----
    (
        "az.login-sp",
        "az login --service-principal -u {U} -p {S} --tenant contoso.onmicrosoft.test",
        Pw,
        Arg,
    ),
    (
        "az.account-key",
        "az storage blob upload --account-name acmedata --account-key {S} -c logs -f app.log",
        Key,
        Arg,
    ),
    (
        "az.admin-password",
        "az vm create -n vm1 -g rg --image Ubuntu2204 --admin-username azureuser --admin-password {S}",
        Pw,
        Arg,
    ),
    (
        "aws.configure-set",
        "aws configure set aws_secret_access_key {S}",
        Key,
        KeyValue,
    ),
    (
        "aws.secret-string",
        "aws secretsmanager create-secret --name prod/db --secret-string {S}",
        Pw,
        Arg,
    ),
    (
        "aws.ssm-value",
        "aws ssm put-parameter --name /app/db/password --type SecureString --value {S}",
        Pw,
        Arg,
    ),
    (
        "aws.rds-master",
        "aws rds create-db-instance --db-instance-identifier db1 --master-username admin --master-user-password {S} --engine postgres",
        Pw,
        Arg,
    ),
    (
        "gcloud.sql-password",
        "gcloud sql users set-password postgres --instance=db1 --password={S}",
        Pw,
        Arg,
    ),
    ("doctl.t", "doctl auth init -t {S}", Tok, Arg),
    (
        "linode.root_pass",
        "linode-cli linodes create --root_pass {S} --type g6-nanode-1",
        Pw,
        Arg,
    ),
    (
        "flyctl.secrets",
        "flyctl secrets set DATABASE_PASSWORD={S} -a api",
        Pw,
        KeyValue,
    ),
    (
        "heroku.config-set",
        "heroku config:set API_SECRET={S} -a acme-api",
        Tok,
        KeyValue,
    ),
    ("vercel.token", "vercel deploy --prod --token {S}", Tok, Arg),
    (
        "terraform.var",
        "terraform apply -var db_password={S} -auto-approve",
        Pw,
        KeyValue,
    ),
    (
        "terraform.var-quoted",
        "terraform plan -var \"admin_password={s}\"",
        Pw,
        KeyValue,
    ),
    (
        "ansible.e",
        "ansible-playbook site.yml -e ansible_become_pass={S}",
        Pw,
        KeyValue,
    ),
    (
        "ansible.extra-vars",
        "ansible-playbook deploy.yml --extra-vars \"db_password={s} env=prod\"",
        Pw,
        KeyValue,
    ),
    ("vault.login", "vault login {S}", Tok, Arg),
    (
        "vault.kv-put",
        "vault kv put secret/app api_key={S}",
        Key,
        KeyValue,
    ),
    (
        "vault.write-secret_id",
        "vault write auth/approle/login role_id=app secret_id={S}",
        Tok,
        KeyValue,
    ),
    (
        "consul.token",
        "consul kv get -token={S} config/app",
        Tok,
        Arg,
    ),
    (
        "nomad.token",
        "nomad job run -token={S} api.nomad",
        Tok,
        Arg,
    ),
    (
        "pulumi.config-set",
        "pulumi config set dbPassword {S}",
        Pw,
        Arg,
    ),
    (
        "mc.alias-set",
        "mc alias set prod https://{H} {U} {S}",
        Key,
        Arg,
    ),
    (
        "s3cmd.secret_key",
        "s3cmd --access_key=ops --secret_key={S} ls s3://backups",
        Key,
        Arg,
    ),
    // ---- crypto and archives ----
    (
        "openssl.passout",
        "openssl pkcs12 -export -in cert.pem -inkey key.pem -out bundle.p12 -passout pass:{S}",
        Pw,
        Arg,
    ),
    (
        "openssl.passin",
        "openssl rsa -in enc.key -out plain.key -passin pass:{S}",
        Pw,
        Arg,
    ),
    (
        "keytool.storepass",
        "keytool -importcert -alias ca -file ca.crt -keystore truststore.jks -storepass {S} -noprompt",
        Pw,
        Arg,
    ),
    (
        "jarsigner.storepass",
        "jarsigner -keystore release.jks -storepass {S} app.apk release",
        Pw,
        Arg,
    ),
    (
        "apksigner.ks-pass",
        "apksigner sign --ks release.jks --ks-pass pass:{S} app.apk",
        Pw,
        Arg,
    ),
    (
        "security.unlock",
        "security unlock-keychain -p {S} build.keychain",
        Pw,
        Arg,
    ),
    (
        "gpg.passphrase",
        "gpg --batch --pinentry-mode loopback --passphrase {S} -d secrets.tar.gpg",
        Pw,
        Arg,
    ),
    (
        "ssh-keygen.N",
        "ssh-keygen -t ed25519 -N {S} -f deploy_key",
        Pw,
        Arg,
    ),
    ("zip.P", "zip -P {S} backup.zip db.sql", Pw, Arg),
    ("unzip.P", "unzip -P {S} backup.zip", Pw, Arg),
    ("7z.p", "7z a -p{S} archive.7z data/", Pw, Arg),
    ("rar.hp", "rar a -hp{S} archive.rar data", Pw, Arg),
    // ---- package managers and build tools ----
    (
        "npm.authtoken",
        "npm config set //registry.npmjs.org/:_authToken {S}",
        Tok,
        KeyValue,
    ),
    (
        "npm.authtoken-eq",
        "npm config set //{H}/:_authToken={S}",
        Tok,
        KeyValue,
    ),
    (
        "yarn.npmAuthToken",
        "yarn config set npmAuthToken {S}",
        Tok,
        KeyValue,
    ),
    (
        "twine.p",
        "twine upload --repository-url https://{H}/simple -u {U} -p {S} dist/*",
        Pw,
        Arg,
    ),
    (
        "uv.publish-token",
        "uv publish --publish-url https://{H}/legacy/ --token {S}",
        Tok,
        Arg,
    ),
    (
        "pip.index-url",
        "pip install --index-url https://{U}:{s}@{H}/simple acme-lib",
        UriPw,
        Connect,
    ),
    (
        "poetry.http-basic",
        "poetry config http-basic.acme {U} {S}",
        Pw,
        Arg,
    ),
    ("cargo.login", "cargo login --registry acme {S}", Tok, Arg),
    (
        "dotnet.nuget-source",
        "dotnet nuget add source https://{H}/v3/index.json -n acme -u {U} -p {S}",
        Pw,
        Arg,
    ),
    (
        "dotnet.nuget-push",
        "dotnet nuget push pkg.nupkg -k {S} -s https://{H}/v3/index.json",
        Key,
        Arg,
    ),
    (
        "mvn.D",
        "mvn deploy -Dgpg.passphrase={S} -DskipTests",
        Pw,
        KeyValue,
    ),
    (
        "gradle.P",
        "./gradlew publish -PsigningPassword={S}",
        Pw,
        KeyValue,
    ),
    (
        "java.D",
        "java -Dspring.datasource.password={S} -jar app.jar",
        Pw,
        KeyValue,
    ),
    (
        "composer.http-basic",
        "composer config http-basic.repo.acme.test {U} {S}",
        Pw,
        Arg,
    ),
    (
        "jfrog.password",
        "jf rt upload \"build/*.zip\" libs-release/ --url https://{H}/artifactory --user {U} --password {S}",
        Pw,
        Arg,
    ),
    (
        "sonar.token",
        "sonar-scanner -Dsonar.host.url=https://{H} -Dsonar.token={S}",
        Tok,
        KeyValue,
    ),
    (
        "newman.env-var",
        "newman run api.json --env-var api_key={S}",
        Key,
        KeyValue,
    ),
    (
        "flutter.dart-define",
        "flutter run --dart-define=API_KEY={S}",
        Key,
        KeyValue,
    ),
    ("wp.user_pass", "wp user update 1 --user_pass={S}", Pw, Arg),
    (
        "wp.admin_password",
        "wp core install --url=example.test --title=Demo --admin_user=admin --admin_password={S} --admin_email=a@example.test",
        Pw,
        Arg,
    ),
    (
        "swaks.auth-password",
        "swaks --to ops@example.test --server {H} --auth LOGIN --auth-user {U} --auth-password {S}",
        Pw,
        Arg,
    ),
    // ---- PowerShell ----
    (
        "pwsh.securestring",
        "ConvertTo-SecureString '{s}' -AsPlainText -Force",
        Pw,
        Arg,
    ),
    (
        "pwsh.invoke-sqlcmd",
        "Invoke-Sqlcmd -ServerInstance {H} -Username sa -Password {S} -Query 'SELECT 1'",
        Pw,
        Arg,
    ),
    (
        "pwsh.client-secret",
        "Connect-MgGraph -TenantId contoso.test -ClientId app -ClientSecret {S}",
        Tok,
        Arg,
    ),
    // ---- wrappers ----
    (
        "bash-c.mysql",
        "bash -c \"mysql -u {U} -p{s} -e 'select 1'\"",
        Pw,
        Arg,
    ),
    (
        "ssh.remote-env",
        "ssh {U}@{H} \"PGPASSWORD={s} psql -U app -c 'select 1'\"",
        Pw,
        Env,
    ),
    (
        "sudo-env.pg_dump",
        "sudo -u postgres env PGPASSWORD={S} pg_dump {DB}",
        Pw,
        Env,
    ),
    (
        "kubectl-exec.mysql",
        "kubectl exec -it deploy/api -- mysql -uroot -p{S} -e 'show databases'",
        Pw,
        Arg,
    ),
    (
        "docker-exec.psql",
        "docker exec -it db psql \"postgresql://{U}:{s}@localhost/{DB}\"",
        UriPw,
        Connect,
    ),
    (
        "chpasswd.stdin",
        "echo '{U}:{s}' | sudo chpasswd",
        Pw,
        Stdin,
    ),
    (
        "sudo-S.stdin",
        "echo {S} | sudo -S systemctl restart nginx",
        Pw,
        Stdin,
    ),
    (
        "timeout.redis",
        "timeout 30 redis-cli -a {S} -h {H} ping",
        Pw,
        Arg,
    ),
    // ---- env assignments ----
    ("export.db_password", "export DB_PASSWORD={S}", Pw, Env),
    ("export.gitlab_token", "export GITLAB_TOKEN={S}", Tok, Env),
    ("export.api_key", "export ACME_API_KEY={S}", Key, Env),
    (
        "env.api_token-prefix",
        "API_TOKEN={S} npm run deploy",
        Tok,
        Env,
    ),
    (
        "export.aws_secret",
        "export AWS_SECRET_ACCESS_KEY={S}",
        Key,
        Env,
    ),
];

/// Commands without a credential (prompts, references, look-alike flags).
pub const NEG_COMMANDS: &[(&str, &str)] = &[
    ("docker.run-port", "docker run -p 8080:80 nginx"),
    (
        "docker.run-port-env",
        "docker run --rm -p 5432:5432 -e POSTGRES_DB={DB} -e LOG_LEVEL=info postgres:16",
    ),
    ("mysql.prompt", "mysql -u root -p {DB}"),
    (
        "mysqldump.prompt",
        "mysqldump -u {U} -p --all-databases > all.sql",
    ),
    ("psql.no-password", "psql -h {H} -U {U} -d {DB} -c \"\\dt\""),
    ("ssh.port", "ssh -p 2222 {U}@{H}"),
    ("scp.port", "scp -P 2222 ./app.tgz {U}@{H}:/srv/"),
    ("git.log-p", "git log -p --stat -- src/auth/password.rs"),
    ("grep.password", "grep -rn \"password\" src/ --include=*.ts"),
    ("rg.token", "rg -n 'token|secret' crates/ -g '!*.lock'"),
    ("npm.test", "npm test -- --watch=false"),
    ("cargo.test", "cargo test -p {N} --locked"),
    (
        "curl.accept",
        "curl -sS -H \"Accept: application/json\" https://{H}/api/v1/status",
    ),
    ("curl.prompt-user", "curl -u {U} https://{H}/api/me"),
    (
        "curl.bearer-ref",
        "curl -H \"Authorization: Bearer $API_TOKEN\" https://{H}/v1/me",
    ),
    (
        "aws.get-secret",
        "aws secretsmanager get-secret-value --secret-id prod/db --query SecretString --output text",
    ),
    (
        "aws.iam-policy",
        "aws iam create-policy --policy-name read-secrets --policy-document '{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"secretsmanager:GetSecretValue\",\"kms:Decrypt\"],\"Resource\":\"*\"}]}'",
    ),
    (
        "gh.secret-stdin",
        "gh secret set DB_PASSWORD < ./secrets/db_password.txt",
    ),
    (
        "docker.login-stdin-ref",
        "echo \"$REGISTRY_PASSWORD\" | docker login -u ci --password-stdin {H}",
    ),
    (
        "docker.login-stdin-file",
        "cat ~/.registry-pass | docker login -u ci --password-stdin {H}",
    ),
    ("openssl.rand", "openssl rand -hex 32"),
    (
        "openssl.passin-env",
        "openssl rsa -in enc.key -passin env:KEY_PASS -out plain.key",
    ),
    (
        "openssl.passin-file",
        "openssl pkcs12 -in bundle.p12 -passin file:/run/secrets/p12pass -nokeys",
    ),
    ("htpasswd.prompt", "htpasswd -c .htpasswd admin"),
    ("pass.show", "pass show {N}/prod/db"),
    ("op.read", "op read op://Engineering/{N}-db/password"),
    ("vault.kv-get", "vault kv get -field=password secret/{N}"),
    ("vault.login-method", "vault login -method=oidc role=dev"),
    (
        "ssh-keygen.empty",
        "ssh-keygen -t ed25519 -N '' -f ./id_deploy",
    ),
    (
        "helm.set-tag",
        "helm upgrade --install {N} ./chart --set image.tag=1.2.3 --set replicaCount=2",
    ),
    (
        "helm.set-secret-name",
        "helm install api ./chart --set auth.existingSecret={N}-creds --set auth.secretKeys.passwordKey=password",
    ),
    (
        "terraform.var-region",
        "terraform apply -var region=eu-west-1 -var instance_count=3",
    ),
    (
        "kubectl.port-forward",
        "kubectl port-forward svc/{N} 5432:5432",
    ),
    (
        "kubectl.get-secret",
        "kubectl get secret {N}-creds -o jsonpath='{.data.password}' | base64 -d",
    ),
    (
        "kubectl.secret-from-file",
        "kubectl create secret generic {N}-tls --from-file=tls.crt=./tls.crt --from-file=tls.key=./tls.key",
    ),
    (
        "sed.password",
        "sed -i 's/password_min_length: 8/password_min_length: 12/' config.yaml",
    ),
    (
        "mysql.password-ref",
        "mysql -u {U} -p\"$(cat ~/.mysql_pw)\" {DB}",
    ),
    (
        "redis.password-ref",
        "redis-cli -a \"$REDIS_PASSWORD\" -h {H} ping",
    ),
    ("export.token-ttl", "export TOKEN_TTL=3600"),
    ("export.max-tokens", "export MAX_TOKENS_PER_TURN=4096"),
    ("export.secret-name", "export DB_SECRET_NAME={N}-creds"),
    ("node-env.prefix", "NODE_ENV=production PORT=3000 npm start"),
    (
        "git.config-user",
        "git config --global user.email dev@example.test",
    ),
    (
        "pip.public-index",
        "pip install -i https://pypi.org/simple requests==2.32.3",
    ),
    (
        "gcloud.print-token",
        "gcloud auth print-access-token --impersonate-service-account={N}@proj.iam.gserviceaccount.com",
    ),
    (
        "jq.password-path",
        "jq -r '.database.password' config/{N}.json",
    ),
    (
        "python.createsuperuser",
        "python manage.py createsuperuser --username admin --email admin@example.test",
    ),
    (
        "az.keyvault-show",
        "az keyvault secret show --vault-name kv-{N} --name db-password --query value -o tsv",
    ),
    (
        "docker.build-secret",
        "docker build --secret id=npmrc,src=$HOME/.npmrc -t acme/web .",
    ),
    (
        "ansible.vault-file",
        "ansible-playbook site.yml --vault-password-file ~/.vault_pass -e env=prod",
    ),
    (
        "terraform.var-ref",
        "terraform apply -var \"db_password=${TF_VAR_db_password}\"",
    ),
    ("psql.env-ref", "PGPASSWORD=$PGPASSWORD psql -h {H} -U {U}"),
    ("sshpass.file", "sshpass -f ~/.ssh/pass.txt ssh {U}@{H}"),
    ("keytool.list", "keytool -list -v -keystore truststore.jks"),
    ("npm.config-get", "npm config get registry"),
    (
        "kubectl.token-review",
        "kubectl auth can-i create secrets --as=system:serviceaccount:{N}:deployer",
    ),
    ("tsc", "npx tsc --noEmit -p tsconfig.json"),
    (
        "pytest.k-token",
        "pytest -k \"test_token_refresh or test_password_reset\" -q",
    ),
    ("ls.secrets-dir", "ls -la ~/.config/{N}/secrets/"),
    ("chmod.key", "chmod 600 ~/.ssh/id_ed25519"),
    (
        "curl.json-no-secret",
        "curl -X POST https://{H}/api/users -H 'Content-Type: application/json' -d '{\"username\":\"{U}\",\"role\":\"viewer\"}'",
    ),
    (
        "mvn.D-skip",
        "mvn -DskipTests -Dmaven.javadoc.skip=true package",
    ),
    (
        "java.D-props",
        "java -Dspring.profiles.active=prod -Dserver.port=8081 -jar app.jar",
    ),
    (
        "gradle.P-version",
        "./gradlew build -Pversion=1.4.0 -PskipSigning=true",
    ),
    (
        "docker.compose-up",
        "docker compose -f docker-compose.yml up -d --build",
    ),
    ("az.login-interactive", "az login --use-device-code"),
    ("gh.auth-status", "gh auth status --show-token=false"),
    (
        "glab.auth-stdin",
        "glab auth login --hostname {H} --stdin < token.txt",
    ),
    ("unzip.list", "unzip -l release.zip"),
    ("7z.list", "7z l -slt archive.7z"),
];

/// Value domain of a config/env name (by its spelling).
pub const POS_CONFIG_NAMES: &[(&str, K)] = &[
    ("password", Pw),
    ("db_password", Pw),
    ("DB_PASSWORD", Pw),
    ("POSTGRES_PASSWORD", Pw),
    ("REDIS_PASSWORD", Pw),
    ("SMTP_PASSWORD", Pw),
    ("adminPassword", Pw),
    ("apiKey", Key),
    ("api_key", Key),
    ("ACME_API_KEY", Key),
    ("client_secret", Tok),
    ("clientSecret", Tok),
    ("auth_token", Tok),
    ("ACCESS_TOKEN", Tok),
    ("JWT_SECRET", Tok),
    ("SESSION_SECRET", Tok),
    ("secret_key", Key),
    ("WEBHOOK_SECRET", Tok),
];

/// Config/env entries without a credential: (id, name, value).
pub const NEG_CONFIG: &[(&str, &str, &str)] = &[
    ("cfg.secret-name", "secretName", "{N}-creds"),
    ("cfg.existing-secret", "existingSecret", "{N}-db"),
    ("cfg.password-policy", "passwordPolicy", "strict"),
    ("cfg.token-url", "tokenUrl", "https://{H}/oauth/token"),
    ("cfg.max-tokens", "maxTokensPerTurn", "4096"),
    ("cfg.max-tokens-env", "MAX_TOKENS", "8192"),
    ("cfg.password-min-length", "password_min_length", "12"),
    ("cfg.token-ttl", "TOKEN_TTL", "3600"),
    ("cfg.auth-mode", "auth", "oauth"),
    ("cfg.api-key-env", "api_key_env", "ACME_API_KEY"),
    ("cfg.passwordless", "passwordless", "true"),
    ("cfg.secret-bool", "secret", "false"),
    ("cfg.password-empty", "password", ""),
    ("cfg.secret-key-ref", "secretKeyRef", "{N}-creds"),
    ("cfg.credentials-ref", "credentialsSecretRef", "{N}-cloud"),
    ("cfg.token-limit", "tokenLimit", "8000"),
    ("cfg.service-account", "serviceAccountName", "{N}-deployer"),
    ("cfg.secret-id", "SecretId", "prod/{N}/db"),
    ("cfg.key-id", "keyId", "{N}-signing"),
    ("cfg.port", "PORT", "8080"),
    ("cfg.node-env", "NODE_ENV", "production"),
    ("cfg.log-level", "LOG_LEVEL", "debug"),
    ("cfg.auth-url", "AUTH_URL", "https://{H}/auth"),
    ("cfg.token-type", "token_type", "Bearer"),
    ("cfg.password-field", "passwordField", "user_password"),
    ("cfg.key-path", "private_key_path", "~/.ssh/id_ed25519"),
    ("cfg.secret-path", "secret_file", "/run/secrets/{N}"),
    ("cfg.token-header", "tokenHeader", "X-Api-Key"),
    ("cfg.iam-action", "Action", "secretsmanager:GetSecretValue"),
    ("cfg.iam-action-kms", "Action", "kms:Decrypt"),
    ("cfg.github-permission", "id-token", "write"),
    ("cfg.secrets-permission", "secrets", "read"),
];

/// Prose with credential words and no credential.
pub const NEG_PROSE: &[(&str, &str)] = &[
    (
        "prose.stored-in-vault",
        "The database password is stored in Vault under secret/{N}/db, never in the repo.",
    ),
    (
        "prose.rotate-token",
        "Rotate the deploy token every 90 days; the CI job reads it from the masked variable.",
    ),
    (
        "prose.max-tokens",
        "Set `maxTokensPerTurn` to 4096 to keep each turn under budget.",
    ),
    (
        "prose.secret-name",
        "The `secretName` field references the Kubernetes Secret `{N}-creds`.",
    ),
    (
        "prose.password-rules",
        "Your password must be at least 12 characters and include a number.",
    ),
    (
        "prose.iam-action",
        "Grant the role `secretsmanager:GetSecretValue` on the prod/{N} prefix only.",
    ),
    (
        "prose.header",
        "The API key is passed via the `X-Api-Key` header, read from `ACME_API_KEY`.",
    ),
    (
        "prose.password-incorrect",
        "The login failed: password is incorrect for user {U}.",
    ),
    (
        "prose.password-in-env",
        "The password is in the .env file, which is gitignored.",
    ),
    (
        "prose.reset",
        "Password reset links expire after 30 minutes.",
    ),
    (
        "prose.token-none",
        "Token: not configured yet, ask the platform team.",
    ),
    (
        "prose.refactor",
        "I refactored `validate_token()` so it returns `Result<Claims, AuthError>` instead of panicking.",
    ),
    (
        "prose.tests",
        "All 214 tests pass, including the new `password_hash_roundtrip` test.",
    ),
    (
        "prose.pin",
        "Pin the dependency to 2.3.1 because 2.4 broke the token refresh flow.",
    ),
    (
        "prose.secret-manager",
        "Secrets come from AWS Secrets Manager; the app only knows the secret ARN.",
    ),
    (
        "prose.oauth",
        "OAuth client credentials flow: exchange client id and secret for an access token.",
    ),
    (
        "prose.key-rotation",
        "Key rotation runs nightly; the old signing key stays valid for 24 hours.",
    ),
    (
        "prose.password-placeholder",
        "Replace <password> with the value from the team vault before running the script.",
    ),
    (
        "prose.secret-type",
        "The secret type is `kubernetes.io/dockerconfigjson`.",
    ),
    (
        "prose.token-count",
        "The prompt used 18,204 tokens; the limit is 200k tokens.",
    ),
];

/// Prose that states a credential: (id, template). Labelled
/// `natural_language`.
pub const POS_PROSE: &[(&str, &str, K)] = &[
    (
        "nl.password-is",
        "connect to the staging db, the password is {s}",
        Pw,
    ),
    (
        "nl.db-password-is",
        "the db password is {s} — please run the migration",
        Pw,
    ),
    ("nl.api-key-colon", "staging api key: {s}", Key),
    (
        "nl.use-password",
        "use password {s} for the admin account on {H}",
        Pw,
    ),
    ("nl.token-is", "my token is {s}, use it for the deploy", Tok),
];

/// Code files without credentials (agent skill scripts).
pub const NEG_CODE: &[(&str, &str)] = &[
    (
        "code.py-env",
        "import os\n\nDB_PASSWORD = os.environ[\"DB_PASSWORD\"]\nTOKEN = os.getenv(\"ACME_TOKEN\", \"\")\n\ndef connect(password: str, token: str | None = None):\n    if not password:\n        raise ValueError(\"password required\")\n    return Client(password=password, token=token)\n",
    ),
    (
        "code.ts-config",
        "export const config = {\n  maxTokensPerTurn: 4096,\n  apiKey: process.env.ACME_API_KEY ?? \"\",\n  secretName: \"db-creds\",\n  password: cfg?.db?.password,\n};\n\nexport function isTokenExpired(token: Token): boolean {\n  return token.expiresAt < Date.now();\n}\n",
    ),
    (
        "code.ts-types",
        "interface AuthState {\n  token: string | null;\n  password: string;\n  refreshToken?: string;\n}\n\nconst initial: AuthState = { token: null, password: \"\", refreshToken: undefined };\n",
    ),
    (
        "code.sh-refs",
        "#!/usr/bin/env bash\nset -euo pipefail\n: \"${DB_PASSWORD:?DB_PASSWORD must be set}\"\nmysql -u \"$DB_USER\" -p\"$DB_PASSWORD\" -h \"$DB_HOST\" \"$DB_NAME\" < schema.sql\ncurl -H \"Authorization: Bearer ${API_TOKEN}\" \"$API_URL/health\"\n",
    ),
    (
        "code.go-struct",
        "type Config struct {\n\tPassword string `json:\"password\" env:\"DB_PASSWORD\"`\n\tToken    string `json:\"token\"`\n}\n\nfunc (c Config) Valid() bool { return c.Password != \"\" && c.Token != \"\" }\n",
    ),
    (
        "code.iam-json",
        "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\"secretsmanager:GetSecretValue\", \"secretsmanager:DescribeSecret\", \"kms:Decrypt\"],\n      \"Resource\": \"arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/*\"\n    }\n  ]\n}\n",
    ),
];

/// YAML documents without credentials (k8s manifests, CI workflows).
pub const NEG_YAML: &[(&str, &str)] = &[
    (
        "yaml.k8s-secret-ref",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      serviceAccountName: api-deployer\n      containers:\n        - name: api\n          image: acme/api:1.4.2\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: db-creds\n                  key: password\n            - name: MAX_TOKENS\n              value: \"4096\"\n      volumes:\n        - name: tls\n          secret:\n            secretName: api-tls\n",
    ),
    (
        "yaml.gha-secrets",
        "name: deploy\non: [push]\npermissions:\n  id-token: write\n  contents: read\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo \"${{ secrets.REGISTRY_PASSWORD }}\" | docker login -u ci --password-stdin registry.example.test\n        env:\n          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}\n          API_TOKEN: ${{ secrets.API_TOKEN }}\n",
    ),
    (
        "yaml.helm-values",
        "auth:\n  existingSecret: db-creds\n  secretKeys:\n    adminPasswordKey: admin-password\n    userPasswordKey: user-password\npassword: \"{{ .Values.global.password }}\"\ntokenTTL: 3600\n",
    ),
    (
        "yaml.compose-refs",
        "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n      POSTGRES_USER: app\n    secrets:\n      - db_password\nsecrets:\n  db_password:\n    file: ./secrets/db_password.txt\n",
    ),
];

pub const HOSTS: &[&str] = &[
    "db.internal.test",
    "10.20.3.14",
    "198.51.100.23",
    "api.acme.test",
    "registry.acme.test",
    "cache-01.corp.example",
    "203.0.113.77",
    "gitlab.example.test",
];
pub const USERS: &[&str] = &["deploy", "admin", "svc_app", "ci-bot", "report", "ops"];
pub const DBS: &[&str] = &["orders", "shop", "analytics", "billing", "app_prod"];
pub const NAMES: &[&str] = &[
    "billing", "orders", "search", "payments", "gateway", "ledger",
];

/// Placeholder-looking values (labelled optional for passwords, negative
/// otherwise).
pub const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "your-password-here",
    "password123",
    "REPLACE_ME",
    "your_api_key",
    "CHANGE_ME_PLEASE",
    "example-token",
    "dummy",
];

/// References to a secret (never secrets themselves), shell-ready.
pub const REFERENCES: &[&str] = &[
    "$DB_PASSWORD",
    "\"${DB_PASSWORD}\"",
    "\"${API_TOKEN:?missing}\"",
    "'${{ secrets.DEPLOY_TOKEN }}'",
    "\"$(cat /run/secrets/db_password)\"",
    "<password>",
    "'<YOUR_TOKEN>'",
    "%DB_PASSWORD%",
    "'{{ .Values.db.password }}'",
    "\"$env:ACME_TOKEN\"",
    "'***'",
];

/// References for config files (unquoted form).
pub const CONFIG_REFERENCES: &[&str] = &[
    "${DB_PASSWORD}",
    "${{ secrets.DEPLOY_TOKEN }}",
    "{{ .Values.db.password }}",
    "<YOUR_API_KEY>",
    "${env:ACME_TOKEN}",
    "***",
    "op://Engineering/db/password",
    "vault://secret/data/app#token",
];

pub const WORDS: &[&str] = &[
    "sunflower",
    "harbor",
    "granite",
    "velvet",
    "orbit",
    "maple",
    "falcon",
    "cobalt",
    "meadow",
    "lantern",
    "pepper",
    "glacier",
    "tundra",
    "copper",
    "willow",
    "nebula",
];
