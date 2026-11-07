//! Table-driven examples for every `cli_tools` entry with a credential
//! argument: at least one command where the entry must report the secret
//! (`POS`) and one look-alike or safe form where nothing may be reported
//! (`NEG`). Syntax follows each tool's own `--help`/man page. All values are
//! invented and match no vendor format.

use agentleaks_core::{Candidate, Route, Routed};
use agentleaks_shell::ShellAnalyzer;
use agentleaks_spec::{ArgForm, ArgKind, Spec};

/// (entry `tool`, command, secret)
const POS: &[(&str, &str, &str)] = &[
    // ---- relational and analytical databases ----
    ("mysql", "mysql -u root -pRq8vLm2Xz shop", "Rq8vLm2Xz"),
    (
        "mysql",
        "mysqldump --password=Rq8vLm2Xz --all-databases",
        "Rq8vLm2Xz",
    ),
    ("mysql", "mysqladmin -u root password Nw7Kq2Lp", "Nw7Kq2Lp"),
    (
        "mysqlsh",
        "mysqlsh --uri root@db.test:3306 --password=Ms7hQ2vX",
        "Ms7hQ2vX",
    ),
    (
        "psql",
        r#"psql "host=db.test user=app password=Pg7xK2mQ dbname=shop""#,
        "Pg7xK2mQ",
    ),
    (
        "psql",
        r#"pg_dump -d "postgresql://app:Pg7xK2mQ@db.test/shop" -Fc"#,
        "Pg7xK2mQ",
    ),
    (
        "sqlcmd",
        r#"sqlcmd -S db.test -U sa -P Sq9mL2xV -Q "select 1""#,
        "Sq9mL2xV",
    ),
    (
        "sqlplus",
        "sqlplus scott/Tg8rW3nb@db.test:1521/ORCL",
        "Tg8rW3nb",
    ),
    (
        "db2",
        "db2 connect to SAMPLE user db2inst1 using Db2pW9xq",
        "Db2pW9xq",
    ),
    (
        "clickhouse-client",
        "clickhouse-client --user default --password Ch7qL2vX --query 'select 1'",
        "Ch7qL2vX",
    ),
    (
        "cqlsh",
        "cqlsh db.test -u cassandra -p Cq8sW2mZ",
        "Cq8sW2mZ",
    ),
    (
        "nodetool",
        "nodetool -u admin -pw Nt7pQ2xL status",
        "Nt7pQ2xL",
    ),
    (
        "cypher-shell",
        "cypher-shell -a bolt://db.test:7687 -u neo4j -p Cy9pR2wK",
        "Cy9pR2wK",
    ),
    (
        "neo4j-admin",
        "neo4j-admin dbms set-initial-password Ne4jP9wQ",
        "Ne4jP9wQ",
    ),
    (
        "arangosh",
        "arangosh --server.username root --server.password Ar7gS2qW",
        "Ar7gS2qW",
    ),
    (
        "influx",
        "influx -username admin -password If8xQ2wL -execute 'SHOW DATABASES'",
        "If8xQ2wL",
    ),
    (
        "influx",
        "influx bucket list --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "couchbase-cli",
        "couchbase-cli server-list -c cb.test -u Administrator -p Cb7sR2xQ",
        "Cb7sR2xQ",
    ),
    (
        "beeline",
        "beeline -u jdbc:hive2://hive.test:10000 -n admin -p Bl9eW2qX",
        "Bl9eW2qX",
    ),
    (
        "isql-fb",
        "isql-fb -user SYSDBA -password Fb7kQ2mX employee.fdb",
        "Fb7kQ2mX",
    ),
    (
        "snowsql",
        "snowsql -a acme-eu -u svc --password Sn7wQ2xL",
        "Sn7wQ2xL",
    ),
    (
        "snow",
        "snow sql -q 'select 1' --password Sw8nQ2xK",
        "Sw8nQ2xK",
    ),
    (
        "usql",
        "usql postgres://app:Us9qL2xW@db.test/shop",
        "Us9qL2xW",
    ),
    (
        "pgcli",
        "pgcli postgres://app:Pc7gQ2xW@db.test/shop",
        "Pc7gQ2xW",
    ),
    ("mycli", "mycli -u root -p My7cQ2xW shop", "My7cQ2xW"),
    (
        "mycli",
        "mycli mysql://root:My7cQ2xW@db.test/shop",
        "My7cQ2xW",
    ),
    (
        "cockroach",
        r#"cockroach sql --url "postgresql://root:Co7cQ2xW@crdb.test:26257/defaultdb""#,
        "Co7cQ2xW",
    ),
    (
        "pgloader",
        "pgloader mysql://root:Pg7lQ2xW@db.test/shop postgresql:///shop",
        "Pg7lQ2xW",
    ),
    (
        "migrate",
        r#"migrate -path ./migrations -database "postgres://app:Mi7gQ2xW@db.test/shop?sslmode=disable" up"#,
        "Mi7gQ2xW",
    ),
    (
        "dbmate",
        r#"dbmate --url "postgres://app:Db7mQ2xW@db.test/shop" up"#,
        "Db7mQ2xW",
    ),
    (
        "atlas",
        r#"atlas schema inspect -u "mysql://root:At7lQ2xW@db.test/shop""#,
        "At7lQ2xW",
    ),
    (
        "flyway",
        "flyway -url=jdbc:postgresql://db.test/shop -user=app -password=Fw7yQ2xW migrate",
        "Fw7yQ2xW",
    ),
    (
        "liquibase",
        "liquibase update --url jdbc:postgresql://db.test/shop --username app --password Lq7bQ2xW",
        "Lq7bQ2xW",
    ),
    (
        "sqlx",
        "sqlx migrate run --database-url postgres://app:Sx7qQ2xW@db.test/shop",
        "Sx7qQ2xW",
    ),
    (
        "prisma",
        r#"prisma migrate diff --from-url "postgresql://app:Pr7sQ2xW@db.test/shop" --to-schema-datamodel schema.prisma"#,
        "Pr7sQ2xW",
    ),
    ("tsql", "tsql -S db.test -U sa -P Ts7qQ2xW", "Ts7qQ2xW"),
    (
        "hdbsql",
        r#"hdbsql -n hana.test:30015 -u SYSTEM -p Hd7bQ2xW "select 1 from dummy""#,
        "Hd7bQ2xW",
    ),
    ("vsql", "vsql -h v.test -U dbadmin -w Vs7qQ2xW", "Vs7qQ2xW"),
    (
        "surreal",
        "surreal sql --endpoint http://s.test:8000 --user root --pass Su7rQ2xW",
        "Su7rQ2xW",
    ),
    // ---- key-value, document, queues, search ----
    (
        "redis-cli",
        "redis-cli -h cache.test -a Rd8sQ2xW ping",
        "Rd8sQ2xW",
    ),
    (
        "redis-cli",
        "redis-cli -u redis://default:Rd8sQ2xW@cache.test:6379 ping",
        "Rd8sQ2xW",
    ),
    (
        "mongosh",
        r#"mongosh "mongodb://app:Mg7oQ2xW@db.test:27017/shop""#,
        "Mg7oQ2xW",
    ),
    (
        "mongosh",
        "mongodump -u app -p Mg7oQ2xW --authenticationDatabase admin",
        "Mg7oQ2xW",
    ),
    (
        "etcdctl",
        "etcdctl --user root:Et7cQ2xW get /config",
        "Et7cQ2xW",
    ),
    (
        "etcdctl",
        "etcdctl --user root --password Et7cQ2xW get /",
        "Et7cQ2xW",
    ),
    (
        "rabbitmqctl",
        "rabbitmqctl add_user deploy Rb7tQ2xW",
        "Rb7tQ2xW",
    ),
    (
        "rabbitmqctl",
        "rabbitmqctl -n rabbit@mq add_user deploy Rb7tQ2xW",
        "Rb7tQ2xW",
    ),
    (
        "rabbitmqadmin",
        "rabbitmqadmin -H mq.test -u admin -p Rm8qW2xL list queues",
        "Rm8qW2xL",
    ),
    (
        "kafka-console-producer",
        "kafka-console-producer --bootstrap-server k.test:9093 --topic t --producer-property ssl.key.password=Kf7kQ2xW",
        "Kf7kQ2xW",
    ),
    (
        "kcat",
        "kcat -b k.test:9093 -X sasl.password=Kc7aQ2xW -L",
        "Kc7aQ2xW",
    ),
    (
        "mosquitto_pub",
        "mosquitto_pub -h mq.test -u dev -P Mq7tQ2xW -t a -m b",
        "Mq7tQ2xW",
    ),
    (
        "mosquitto_passwd",
        "mosquitto_passwd -b /etc/mosquitto/passwd dev Mp7wQ2xL",
        "Mp7wQ2xL",
    ),
    (
        "nats",
        "nats pub --user dev --password Na7tQ2xW orders hello",
        "Na7tQ2xW",
    ),
    (
        "nats",
        "nats sub --token q8ZrT2mVx9LpK4wN orders",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "memtier_benchmark",
        "memtier_benchmark -s cache.test -a Me7mQ2xW",
        "Me7mQ2xW",
    ),
    (
        "redis-server",
        "redis-server --requirepass Rs7vQ2xW --port 6380",
        "Rs7vQ2xW",
    ),
    (
        "meilisearch",
        "meilisearch --master-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "typesense-server",
        "typesense-server --data-dir /data --api-key=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "elasticsearch-users",
        "elasticsearch-users useradd dev -p El7sQ2xW -r superuser",
        "El7sQ2xW",
    ),
    (
        "rpk",
        "rpk topic list --user dev --password Rp7kQ2xW --sasl-mechanism SCRAM-SHA-256",
        "Rp7kQ2xW",
    ),
    // ---- remote access and sysadmin ----
    (
        "sshpass",
        "sshpass -p Ss7hQ2xW ssh dev@host.test",
        "Ss7hQ2xW",
    ),
    (
        "xfreerdp",
        "xfreerdp /v:host.test /u:admin /p:Xf7rQ2xW",
        "Xf7rQ2xW",
    ),
    (
        "rdesktop",
        "rdesktop -u admin -p Rd7kQ2xW host.test",
        "Rd7kQ2xW",
    ),
    (
        "smbclient",
        "smbclient //fs.test/share -U admin%Sm7bQ2xW",
        "Sm7bQ2xW",
    ),
    (
        "mount",
        "mount -t cifs //fs.test/d /mnt -o username=dev,password=Mt7nQ2xW",
        "Mt7nQ2xW",
    ),
    (
        "sshfs",
        "sshfs dev@host.test:/srv /mnt -o password=Sf7sQ2xW",
        "Sf7sQ2xW",
    ),
    (
        "lftp",
        "lftp -u deploy,Lf7tQ2xW sftp://host.test",
        "Lf7tQ2xW",
    ),
    (
        "ncftp",
        "ncftpput -u dev -p Nc7fQ2xW ftp.test /pub file.txt",
        "Nc7fQ2xW",
    ),
    (
        "plink",
        "plink -ssh dev@host.test -pw Pl7kQ2xW uptime",
        "Pl7kQ2xW",
    ),
    (
        "winscp.com",
        r#"winscp.com /command "open sftp://dev:Ws7cQ2xW@host.test/" "exit""#,
        "Ws7cQ2xW",
    ),
    (
        "ipmitool",
        "ipmitool -I lanplus -H bmc.test -U ADMIN -P Ip7mQ2xW power status",
        "Ip7mQ2xW",
    ),
    (
        "racadm",
        "racadm -r idrac.test -u root -p Rc7dQ2xW getsysinfo",
        "Rc7dQ2xW",
    ),
    (
        "snmpwalk",
        "snmpwalk -v2c -c Cm7nQ2xW 10.0.0.1 system",
        "Cm7nQ2xW",
    ),
    ("x11vnc", "x11vnc -passwd Vn7cQ2xW -display :0", "Vn7cQ2xW"),
    (
        "VBoxManage",
        "VBoxManage guestcontrol vm1 run --username dev --password Vb7xQ2wL -- /bin/ls",
        "Vb7xQ2wL",
    ),
    (
        "vmrun",
        "vmrun -T ws -gu dev -gp Vm7rQ2xW runProgramInGuest vm.vmx /bin/ls",
        "Vm7rQ2xW",
    ),
    (
        "ovftool",
        r#"ovftool vm.ova "vi://admin:Ov7fQ2xW@vc.test/DC/host/h1""#,
        "Ov7fQ2xW",
    ),
    (
        "openstack",
        "openstack --os-username dev --os-password Os7tQ2xW server list",
        "Os7tQ2xW",
    ),
    (
        "pvesh",
        "pvesh set /access/password --userid dev@pve --password Pv7eQ2xW",
        "Pv7eQ2xW",
    ),
    (
        "ldapsearch",
        "ldapsearch -x -D cn=admin,dc=x -w Ld7pQ2xW -b dc=x",
        "Ld7pQ2xW",
    ),
    (
        "ldappasswd",
        "ldappasswd -x -D cn=admin,dc=x -W -s Lp7wQ2xN uid=dev,dc=x",
        "Lp7wQ2xN",
    ),
    (
        "net",
        r"net use \\fs\share Nt7uQ2xW /user:ACME\dev",
        "Nt7uQ2xW",
    ),
    (
        "net",
        r"net use Z: \\fs\share Nt7uQ2xW /persistent:no",
        "Nt7uQ2xW",
    ),
    ("net", "net user dev Nu7sQ2xW /add", "Nu7sQ2xW"),
    (
        "cmdkey",
        "cmdkey /generic:TERMSRV/host /user:dev /pass:Ck7mQ2xW",
        "Ck7mQ2xW",
    ),
    (
        "schtasks",
        "schtasks /Create /TN job /TR app.exe /SC daily /RU dev /RP Sc7hQ2xW",
        "Sc7hQ2xW",
    ),
    (
        "sc",
        r"sc config svc obj= ACME\dev password= Sv7cQ2xW",
        "Sv7cQ2xW",
    ),
    (
        "psexec",
        r"psexec \\host -u dev -p Ps7xQ2wL cmd",
        "Ps7xQ2wL",
    ),
    (
        "wmic",
        "wmic /node:host /user:dev /password:Wm7iQ2xW process list",
        "Wm7iQ2xW",
    ),
    (
        "winrs",
        "winrs -r:host -u:dev -p:Wr7sQ2xW ipconfig",
        "Wr7sQ2xW",
    ),
    ("usermod", "usermod -p Um7oQ2xW dev", "Um7oQ2xW"),
    (
        "htpasswd",
        "htpasswd -b .htpasswd admin Ht7pQ2xW",
        "Ht7pQ2xW",
    ),
    (
        "htpasswd",
        "htpasswd -bc .htpasswd admin Ht7pQ2xW",
        "Ht7pQ2xW",
    ),
    (
        "nmcli",
        "nmcli dev wifi connect HomeNet password Nm7cQ2xW",
        "Nm7cQ2xW",
    ),
    (
        "wpa_passphrase",
        "wpa_passphrase HomeNet Wp7aQ2xW",
        "Wp7aQ2xW",
    ),
    (
        "iwctl",
        "iwctl --passphrase Iw7cQ2xW station wlan0 connect HomeNet",
        "Iw7cQ2xW",
    ),
    (
        "netsh",
        "netsh wlan set hostednetwork mode=allow ssid=Net key=Ns7hQ2xW",
        "Ns7hQ2xW",
    ),
    (
        "kadmin",
        r#"kadmin -p admin/admin -w Ka7dQ2xW -q "listprincs""#,
        "Ka7dQ2xW",
    ),
    (
        "samba-tool",
        "samba-tool user create dev Sa7mQ2xW",
        "Sa7mQ2xW",
    ),
    (
        "samba-tool",
        "samba-tool user setpassword dev --newpassword=Sa7mQ2xW",
        "Sa7mQ2xW",
    ),
    // ---- offensive tooling ----
    ("netexec", "nxc smb 10.0.0.5 -u dev -p Nx7eQ2xW", "Nx7eQ2xW"),
    (
        "impacket",
        "secretsdump.py 'ACME/dev:Im7pQ2xW@10.0.0.5'",
        "Im7pQ2xW",
    ),
    (
        "evil-winrm",
        "evil-winrm -i 10.0.0.5 -u Administrator -p Ev7wQ2xL",
        "Ev7wQ2xL",
    ),
    (
        "hydra",
        "hydra -l admin -p Hy7dQ2xW ssh://10.0.0.5",
        "Hy7dQ2xW",
    ),
    // ---- HTTP clients ----
    (
        "curl",
        "curl -u admin:Cu7rQ2xW https://api.test/",
        "Cu7rQ2xW",
    ),
    (
        "curl",
        "curl https://admin:Cu7rQ2xW@api.test/health",
        "Cu7rQ2xW",
    ),
    (
        "curl",
        r#"curl -H "Authorization: Bearer q8ZrT2mVx9LpK4wN" https://api.test/"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "curl",
        "curlie -u admin:Cu7rQ2xW https://api.test/",
        "Cu7rQ2xW",
    ),
    (
        "wget",
        "wget --http-user=dev --http-password=Wg7eQ2xW https://h.test/f",
        "Wg7eQ2xW",
    ),
    ("wget", "wget https://dev:Wg7eQ2xW@h.test/f", "Wg7eQ2xW"),
    (
        "http",
        "http -a dev:Ht7tQ2xW GET https://api.test/me",
        "Ht7tQ2xW",
    ),
    (
        "http",
        "http POST https://api.test/login password=Ht7tQ2xW",
        "Ht7tQ2xW",
    ),
    (
        "aria2c",
        "aria2c --http-user=dev --http-passwd=Ar7iQ2xW https://h.test/f",
        "Ar7iQ2xW",
    ),
    (
        "lynx",
        "lynx -auth=dev:Ly7nQ2xW https://h.test/",
        "Ly7nQ2xW",
    ),
    (
        "grpcurl",
        r#"grpcurl -H "authorization: Bearer q8ZrT2mVx9LpK4wN" api.test:443 list"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "websocat",
        "wscat -c wss://ws.test --auth dev:Wc7sQ2xW",
        "Wc7sQ2xW",
    ),
    (
        "ab",
        "ab -n 100 -A dev:Ab7nQ2xW https://h.test/",
        "Ab7nQ2xW",
    ),
    (
        "hey",
        "hey -n 100 -a dev:He7yQ2xW https://h.test/",
        "He7yQ2xW",
    ),
    (
        "Invoke-WebRequest",
        r#"Invoke-RestMethod -Uri https://api.test -Headers @{Authorization="Bearer q8ZrT2mVx9LpK4wN"}"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    ("hurl", "hurl --user dev:Hu7rQ2xW test.hurl", "Hu7rQ2xW"),
    // ---- VCS and CI ----
    (
        "git",
        "git clone https://dev:Gt7cQ2xW@git.test/acme/app.git",
        "Gt7cQ2xW",
    ),
    (
        "git",
        r#"git -c http.extraHeader="Authorization: Bearer q8ZrT2mVx9LpK4wN" fetch"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "svn",
        "svn checkout https://svn.test/trunk --username dev --password Sv7nQ2xW",
        "Sv7nQ2xW",
    ),
    ("p4", "p4 -u dev -P Pf7oQ2xW sync", "Pf7oQ2xW"),
    (
        "hg",
        "hg --config auth.x.password=Hg7mQ2xW pull",
        "Hg7mQ2xW",
    ),
    (
        "cvs",
        "cvs -d :pserver:dev:Cv7sQ2xW@cvs.test:/repo checkout mod",
        "Cv7sQ2xW",
    ),
    (
        "gh",
        "gh secret set API_KEY --body q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "gh",
        r#"gh api -H "Authorization: token q8ZrT2mVx9LpK4wN" /user"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "glab",
        "glab auth login --hostname gl.test --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("glab", "glab variable set DB_PASSWORD Gl7bQ2xW", "Gl7bQ2xW"),
    (
        "tea",
        "tea login add --url https://gitea.test --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "gitlab-runner",
        "gitlab-runner register --url https://gl.test --registration-token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "circleci",
        "circleci setup --token q8ZrT2mVx9LpK4wN --host https://circleci.test",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "travis",
        "travis login --github-token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "buildkite-agent",
        "buildkite-agent start --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "drone",
        "drone secret add --repo acme/app --name db_password --data Dr7nQ2xW",
        "Dr7nQ2xW",
    ),
    (
        "act",
        "act -s GITHUB_TOKEN=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "gitea",
        "gitea admin user create --username dev --password Gi7tQ2xW --email d@x.test",
        "Gi7tQ2xW",
    ),
    ("codecov", "codecov -t q8ZrT2mVx9LpK4wN", "q8ZrT2mVx9LpK4wN"),
    (
        "sentry-cli",
        "sentry-cli --auth-token q8ZrT2mVx9LpK4wN releases list",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("snyk", "snyk auth q8ZrT2mVx9LpK4wN", "q8ZrT2mVx9LpK4wN"),
    (
        "fossa",
        "fossa analyze --fossa-api-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "postman",
        "postman login --with-api-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "bru",
        "bru run --env-var apiKey=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "jenkins-cli",
        "jenkins-cli -s https://ci.test/ -auth dev:Jk7nQ2xW build job",
        "Jk7nQ2xW",
    ),
    (
        "jenkins-cli",
        "java -jar jenkins-cli.jar -s https://ci.test/ -auth dev:Jk7nQ2xW build job",
        "Jk7nQ2xW",
    ),
    // ---- containers and orchestration ----
    (
        "docker",
        "docker login -u ci -p Dk7rQ2xW reg.test",
        "Dk7rQ2xW",
    ),
    (
        "docker",
        "podman login reg.test --username ci --password=Dk7rQ2xW",
        "Dk7rQ2xW",
    ),
    (
        "docker-compose",
        "docker-compose run -e DB_PASSWORD=Dc7oQ2xW app migrate",
        "Dc7oQ2xW",
    ),
    (
        "skopeo",
        "skopeo copy --src-creds dev:Sk7oQ2xW docker://a docker://b",
        "Sk7oQ2xW",
    ),
    (
        "skopeo",
        "skopeo login -u dev -p Sk7oQ2xW reg.test",
        "Sk7oQ2xW",
    ),
    (
        "crane",
        "crane auth login reg.test -u dev -p Cr7nQ2xW",
        "Cr7nQ2xW",
    ),
    (
        "helm",
        "helm repo add acme https://charts.test --username dev --password Hm7lQ2xW",
        "Hm7lQ2xW",
    ),
    (
        "helm",
        "helm install api ./chart --set db.password=Hm7lQ2xW",
        "Hm7lQ2xW",
    ),
    (
        "helmfile",
        "helmfile apply --state-values-set db.password=Hf7lQ2xW",
        "Hf7lQ2xW",
    ),
    (
        "kubectl",
        "kubectl create secret generic db --from-literal=password=Kb7cQ2xW",
        "Kb7cQ2xW",
    ),
    (
        "kubectl",
        "kubectl --token=q8ZrT2mVx9LpK4wN get pods",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "kubectl",
        "oc login https://api.ocp.test:6443 -u dev -p Kb7cQ2xW",
        "Kb7cQ2xW",
    ),
    (
        "kustomize",
        "kustomize edit add secret db --from-literal=password=Ku7sQ2xW",
        "Ku7sQ2xW",
    ),
    (
        "argocd",
        "argocd login argo.test --username admin --password Ag7cQ2xW",
        "Ag7cQ2xW",
    ),
    (
        "argo",
        "argo list --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "flux",
        "flux create secret git repo-auth --url=https://git.test/x --username=dev --password=Fx7lQ2xW",
        "Fx7lQ2xW",
    ),
    (
        "rancher",
        "rancher login https://rancher.test --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "kubeadm",
        "kubeadm join 10.0.0.1:6443 --token q8ZrT2mVx9LpK4wN --discovery-token-unsafe-skip-ca-verification",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "k3s",
        "k3s agent --server https://k3s.test:6443 --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "ctr",
        "ctr images pull --user dev:Ct7rQ2xW reg.test/app:1",
        "Ct7rQ2xW",
    ),
    (
        "crictl",
        "crictl pull --creds dev:Cr7iQ2xW reg.test/app:1",
        "Cr7iQ2xW",
    ),
    (
        "trivy",
        "trivy image --username dev --password Tr7vQ2xW reg.test/app:1",
        "Tr7vQ2xW",
    ),
    (
        "cosign",
        "cosign login reg.test -u dev -p Co7sQ2xW",
        "Co7sQ2xW",
    ),
    // ---- cloud and platform CLIs ----
    (
        "az",
        "az login --service-principal -u app -p Az7lQ2xW --tenant t.test",
        "Az7lQ2xW",
    ),
    (
        "az",
        "az storage blob list --account-name x --account-key q8ZrT2mVx9LpK4wNa8b7c6d5",
        "q8ZrT2mVx9LpK4wNa8b7c6d5",
    ),
    (
        "aws",
        "aws configure set aws_secret_access_key q8ZrT2mVx9LpK4wN/a8b7c6d5e4f3g2h1i0j9k8l7",
        "q8ZrT2mVx9LpK4wN/a8b7c6d5e4f3g2h1i0j9k8l7",
    ),
    (
        "aws",
        "aws secretsmanager put-secret-value --secret-id x --secret-string Aw7sQ2xW",
        "Aw7sQ2xW",
    ),
    (
        "aws",
        "aws cognito-idp admin-create-user --user-pool-id p --username dev --temporary-password Aw7sQ2xW",
        "Aw7sQ2xW",
    ),
    (
        "gcloud",
        "gcloud sql users set-password postgres --instance=db1 --password=Gc7lQ2xW",
        "Gc7lQ2xW",
    ),
    (
        "doctl",
        "doctl auth init -t q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "linode-cli",
        "linode-cli linodes create --root_pass Ln7dQ2xW",
        "Ln7dQ2xW",
    ),
    (
        "flyctl",
        "flyctl secrets set DATABASE_PASSWORD=Fy7lQ2xW",
        "Fy7lQ2xW",
    ),
    (
        "flyctl",
        "fly deploy -t q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "heroku",
        "heroku config:set API_SECRET=Hk7rQ2xW -a app",
        "Hk7rQ2xW",
    ),
    (
        "vercel",
        "vercel deploy --prod --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "netlify",
        "netlify deploy --prod --auth q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("supabase", "supabase db push -p Sb7pQ2xW", "Sb7pQ2xW"),
    (
        "supabase",
        "supabase db dump --db-url postgresql://postgres:Sb7pQ2xW@db.test:5432/postgres",
        "Sb7pQ2xW",
    ),
    (
        "azcopy",
        r#"azcopy copy ./f "https://acct.blob.core.windows.test/c?sv=2024-01-01&sig=Az9cQ2xWq8ZrT2mVx9LpK4wN""#,
        "Az9cQ2xWq8ZrT2mVx9LpK4wN",
    ),
    (
        "rclone",
        "rclone config create s3r s3 secret_access_key q8ZrT2mVx9LpK4wNa8b7c6d5",
        "q8ZrT2mVx9LpK4wNa8b7c6d5",
    ),
    ("rclone", "rclone obscure Rc7lQ2xW", "Rc7lQ2xW"),
    (
        "s3cmd",
        "s3cmd --access_key=AK --secret_key=q8ZrT2mVx9LpK4wN ls",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "mc",
        "mc alias set prod https://s3.test minio-admin q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "gsutil",
        r#"gsutil -o "Credentials:gs_secret_access_key=q8ZrT2mVx9LpK4wN" ls gs://b"#,
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "databricks",
        "databricks fs ls dbfs:/ --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "terraform",
        "terraform apply -var db_password=Tf7rQ2xW",
        "Tf7rQ2xW",
    ),
    (
        "terraform",
        r#"terraform init -backend-config="password=Tf7rQ2xW""#,
        "Tf7rQ2xW",
    ),
    (
        "pulumi",
        "pulumi config set dbPassword Pu7lQ2xW",
        "Pu7lQ2xW",
    ),
    (
        "pulumi",
        "pulumi config set --secret stripeWebhook Pu7lQ2xW",
        "Pu7lQ2xW",
    ),
    (
        "ansible",
        "ansible-playbook site.yml -e ansible_password=An7sQ2xW",
        "An7sQ2xW",
    ),
    (
        "ibmcloud",
        "ibmcloud login -u dev@x.test -p Ib7mQ2xW",
        "Ib7mQ2xW",
    ),
    (
        "ibmcloud",
        "ibmcloud login --apikey q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "scw",
        "scw init secret-key=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "civo",
        "civo apikey save prod q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "aliyun",
        "aliyun configure set --access-key-id AK --access-key-secret q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "cf",
        "cf login -a https://api.cf.test -u dev -p Cf7lQ2xW",
        "Cf7lQ2xW",
    ),
    ("cf", "cf auth dev Cf7lQ2xW", "Cf7lQ2xW"),
    (
        "ngrok",
        "ngrok config add-authtoken q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "ngrok",
        "ngrok http 8080 --basic-auth dev:Ng7rQ2xW",
        "Ng7rQ2xW",
    ),
    (
        "cloudflared",
        "cloudflared tunnel run --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "tailscale",
        "tailscale up --authkey=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("mitmproxy", "mitmdump --proxyauth dev:Mi7tQ2xW", "Mi7tQ2xW"),
    (
        "pscale",
        "pscale database list --org acme --service-token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "neonctl",
        "neonctl projects list --api-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "stripe",
        "stripe listen --api-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "auth0",
        "auth0 login --domain t.test --client-id cid --client-secret q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    // ---- secret managers ----
    ("vault", "vault login q8ZrT2mVx9LpK4wN", "q8ZrT2mVx9LpK4wN"),
    (
        "vault",
        "vault kv put secret/app api_key=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "vault",
        "bao write database/config/db password=Bo7aQ2xW",
        "Bo7aQ2xW",
    ),
    (
        "consul",
        "consul kv get -token=q8ZrT2mVx9LpK4wN config/app",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "consul",
        "consul kv put config/db/password Cn7sQ2xW",
        "Cn7sQ2xW",
    ),
    (
        "nomad",
        "nomad job run -token=q8ZrT2mVx9LpK4wN api.nomad",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "boundary",
        "boundary authenticate password -login-name dev -password=Bd7yQ2xW",
        "Bd7yQ2xW",
    ),
    ("bw", "bw unlock Bw7uQ2xW", "Bw7uQ2xW"),
    ("bw", "bw login dev@example.test Bw7uQ2xW", "Bw7uQ2xW"),
    (
        "bws",
        "bws secret list --access-token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "doppler",
        "doppler secrets set DB_PASSWORD Dp7lQ2xW",
        "Dp7lQ2xW",
    ),
    (
        "doppler",
        "doppler secrets set STRIPE_HOOK=Dp7lQ2xW",
        "Dp7lQ2xW",
    ),
    (
        "infisical",
        "infisical secrets set API_KEY=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "chamber",
        "chamber write api db_password Ch7mQ2xW",
        "Ch7mQ2xW",
    ),
    (
        "akeyless",
        "akeyless auth --access-id p-123 --access-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("conjur", "conjur login -i admin -p Cj7rQ2xW", "Cj7rQ2xW"),
    (
        "ansible-vault",
        "ansible-vault encrypt_string --vault-password-file ~/.vp 'Av7lQ2xW' --name db_password",
        "Av7lQ2xW",
    ),
    // ---- crypto, keys, archives ----
    (
        "openssl",
        "openssl rsa -in k.pem -passin pass:Op7sQ2xW -out p.pem",
        "Op7sQ2xW",
    ),
    (
        "openssl",
        "openssl passwd -6 -salt xyz Op7sQ2xW",
        "Op7sQ2xW",
    ),
    (
        "keytool",
        "keytool -list -keystore k.jks -storepass Kt7lQ2xW",
        "Kt7lQ2xW",
    ),
    (
        "jarsigner",
        "jarsigner -keystore k.jks -storepass Js7gQ2xW app.jar key",
        "Js7gQ2xW",
    ),
    (
        "apksigner",
        "apksigner sign --ks k.jks --ks-pass pass:Ap7kQ2xW app.apk",
        "Ap7kQ2xW",
    ),
    (
        "signtool",
        "signtool sign /f cert.pfx /p St7gQ2xW app.exe",
        "St7gQ2xW",
    ),
    (
        "codesign",
        "security unlock-keychain -p Cs7dQ2xW build.keychain",
        "Cs7dQ2xW",
    ),
    (
        "codesign",
        "security add-generic-password -a dev -s api -w Cs7dQ2xW",
        "Cs7dQ2xW",
    ),
    (
        "codesign",
        "xcrun notarytool submit app.zip --apple-id dev@x.test --password Cs7dQ2xW",
        "Cs7dQ2xW",
    ),
    (
        "altool",
        "xcrun altool --upload-app -f app.ipa -u dev@example.test -p Al7tQ2xW",
        "Al7tQ2xW",
    ),
    (
        "certutil",
        "certutil -p Ce7rQ2xW -importpfx cert.pfx",
        "Ce7rQ2xW",
    ),
    (
        "pk12util",
        "pk12util -i c.p12 -d sql:db -W Pk7uQ2xW",
        "Pk7uQ2xW",
    ),
    (
        "gpg",
        "gpg --batch --passphrase Gp7gQ2xW -d f.gpg",
        "Gp7gQ2xW",
    ),
    (
        "ssh-keygen",
        "ssh-keygen -t ed25519 -N Sk7gQ2xW -f k",
        "Sk7gQ2xW",
    ),
    ("zip", "zip -P Zp7iQ2xW out.zip f", "Zp7iQ2xW"),
    ("unzip", "unzip -P Uz7pQ2xW in.zip", "Uz7pQ2xW"),
    ("7z", "7z x -pSz7pQ2xW a.7z", "Sz7pQ2xW"),
    ("rar", "rar a -hpRr7aQ2xW a.rar dir", "Rr7aQ2xW"),
    (
        "pdftk",
        "pdftk in.pdf output out.pdf user_pw Pd7fQ2xW",
        "Pd7fQ2xW",
    ),
    (
        "pdftk",
        "qpdf --password=Pd7fQ2xW --decrypt in.pdf out.pdf",
        "Pd7fQ2xW",
    ),
    (
        "veracrypt",
        "veracrypt --text --mount v.hc /mnt --password Vc7rQ2xW",
        "Vc7rQ2xW",
    ),
    (
        "restic",
        "restic -r rest:https://dev:Rs7tQ2xW@backup.test/repo snapshots",
        "Rs7tQ2xW",
    ),
    (
        "kopia",
        "kopia repository connect filesystem --path /b --password Ko7pQ2xW",
        "Ko7pQ2xW",
    ),
    (
        "certbot",
        "certbot certonly --eab-kid kid1 --eab-hmac-key q8ZrT2mVx9LpK4wN -d x.test",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "pkcs11-tool",
        "pkcs11-tool --login --pin 4829 --list-objects",
        "4829",
    ),
    (
        "ykman",
        "ykman piv keys generate --pin 482913 9a pub.pem",
        "482913",
    ),
    (
        "yubico-piv-tool",
        "yubico-piv-tool -a verify-pin -P 482913",
        "482913",
    ),
    ("mkpasswd", "mkpasswd -m sha-512 Mk7pQ2xW", "Mk7pQ2xW"),
    (
        "caddy",
        "caddy hash-password --plaintext Ca7dQ2xW",
        "Ca7dQ2xW",
    ),
    // ---- package managers and build tools ----
    (
        "npm",
        "npm config set //registry.npmjs.org/:_authToken q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "yarn",
        "yarn config set npmAuthToken q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "twine",
        "twine upload -u __token__ -p Tw7nQ2xW dist/*",
        "Tw7nQ2xW",
    ),
    (
        "uv",
        "uv publish --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "uv",
        "uv pip install --index-url https://dev:Uv7pQ2xW@pkgs.test/simple x",
        "Uv7pQ2xW",
    ),
    (
        "pip",
        "pip install -i https://dev:Pi7pQ2xW@pkgs.test/simple x",
        "Pi7pQ2xW",
    ),
    (
        "poetry",
        "poetry config http-basic.acme dev Po7eQ2xW",
        "Po7eQ2xW",
    ),
    (
        "poetry",
        "poetry config pypi-token.pypi q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "bundle",
        "bundle config set gems.acme.test dev:Bu7nQ2xW",
        "Bu7nQ2xW",
    ),
    ("cargo", "cargo login q8ZrT2mVx9LpK4wN", "q8ZrT2mVx9LpK4wN"),
    (
        "cargo",
        "cargo login --registry acme q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "dotnet",
        "dotnet nuget add source https://n.test/v3/index.json -n acme -u dev -p Dn7tQ2xW",
        "Dn7tQ2xW",
    ),
    (
        "dotnet",
        "dotnet nuget push p.nupkg -k q8ZrT2mVx9LpK4wN -s https://n.test",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "nuget",
        "nuget sources add -Name acme -Source https://n.test -Password Nu7gQ2xW",
        "Nu7gQ2xW",
    ),
    (
        "nuget",
        "nuget setapikey q8ZrT2mVx9LpK4wN -Source https://n.test",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("mvn", "mvn deploy -Dgpg.passphrase=Mv7nQ2xW", "Mv7nQ2xW"),
    (
        "gradle",
        "./gradlew publish -PsigningPassword=Gr7dQ2xW",
        "Gr7dQ2xW",
    ),
    (
        "java",
        "java -Djavax.net.ssl.keyStorePassword=Jv7aQ2xW -jar app.jar",
        "Jv7aQ2xW",
    ),
    (
        "composer",
        "composer config http-basic.repo.test dev Cp7mQ2xW",
        "Cp7mQ2xW",
    ),
    (
        "composer",
        "composer config --global github-oauth.github.com q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "jfrog",
        "jf rt ping --url https://a.test --user dev --password Jf7rQ2xW",
        "Jf7rQ2xW",
    ),
    (
        "sonar-scanner",
        "sonar-scanner -Dsonar.token=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "flutter",
        "flutter build apk --dart-define=API_KEY=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "newman",
        "newman run c.json --env-var api_key=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "conan",
        "conan remote login acme dev -p Cn7aQ2xW",
        "Cn7aQ2xW",
    ),
    (
        "hatch",
        "hatch publish -u __token__ -a Ha7tQ2xW",
        "Ha7tQ2xW",
    ),
    ("pdm", "pdm publish -u dev -P Pd7mQ2xW", "Pd7mQ2xW"),
    (
        "maturin",
        "maturin upload -u dev -p Ma7tQ2xW dist/*",
        "Ma7tQ2xW",
    ),
    (
        "ant",
        "ant -Dkeystore.password=An7tQ2xW release",
        "An7tQ2xW",
    ),
    (
        "hadoop",
        "hadoop fs -D fs.s3a.secret.key=q8ZrT2mVx9LpK4wN -ls s3a://b/",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "spark-submit",
        "spark-submit --conf spark.hadoop.fs.s3a.secret.key=q8ZrT2mVx9LpK4wN app.py",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "choco",
        "choco push pkg.nupkg --source https://c.test --api-key q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "Publish-Module",
        "Publish-Module -Name Acme -NuGetApiKey q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "ansible-galaxy",
        "ansible-galaxy collection publish x.tar.gz --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    // ---- app CLIs and frameworks ----
    ("wp", "wp user update 1 --user_pass=Wp7uQ2xW", "Wp7uQ2xW"),
    ("wp", "wp config set DB_PASSWORD Wp7uQ2xW", "Wp7uQ2xW"),
    ("drush", "drush upwd admin Dr7uQ2xW", "Dr7uQ2xW"),
    ("drush", "drush si --account-pass=Dr7uQ2xW", "Dr7uQ2xW"),
    (
        "swaks",
        "swaks --to a@example.test --auth-user dev --auth-password Sw7kQ2xW",
        "Sw7kQ2xW",
    ),
    (
        "msmtp",
        "sendemail -f a@x.test -t b@x.test -xu dev -xp Ms7mQ2xW",
        "Ms7mQ2xW",
    ),
    (
        "kcadm.sh",
        "kcadm.sh config credentials --server http://kc.test --realm master --user admin --password Kc7aQ2xW",
        "Kc7aQ2xW",
    ),
    ("kc.sh", "kc.sh start --db-password Kc7sQ2xW", "Kc7sQ2xW"),
    (
        "grafana-cli",
        "grafana-cli admin reset-admin-password Gf7nQ2xW",
        "Gf7nQ2xW",
    ),
    (
        "logcli",
        "logcli query '{app=\"api\"}' --username dev --password Lc7gQ2xW",
        "Lc7gQ2xW",
    ),
    (
        "huggingface-cli",
        "huggingface-cli login --token q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    ("wandb", "wandb login q8ZrT2mVx9LpK4wN", "q8ZrT2mVx9LpK4wN"),
    (
        "dvc",
        "dvc remote modify --local storage password Dv7cQ2xW",
        "Dv7cQ2xW",
    ),
    (
        "jupyter",
        "jupyter lab --ServerApp.token=q8ZrT2mVx9LpK4wN",
        "q8ZrT2mVx9LpK4wN",
    ),
    (
        "airflow",
        "airflow users create -u admin -p Af7lQ2xW -r Admin -e a@x.test -f A -l B",
        "Af7lQ2xW",
    ),
    (
        "superset",
        "superset fab create-admin --username admin --password Su7pQ2xW",
        "Su7pQ2xW",
    ),
    (
        "strapi",
        "strapi admin:create-user --email a@x.test --password Sr7aQ2xW",
        "Sr7aQ2xW",
    ),
    (
        "directus",
        "directus users create --email a@x.test --password Di7rQ2xW --role r1",
        "Di7rQ2xW",
    ),
    // ---- PowerShell ----
    (
        "ConvertTo-SecureString",
        "ConvertTo-SecureString 'Cv7tQ2xW' -AsPlainText -Force",
        "Cv7tQ2xW",
    ),
    (
        "New-LocalUser",
        "Set-ADAccountPassword -Identity dev -NewPassword Nl7oQ2xW -Reset",
        "Nl7oQ2xW",
    ),
    (
        "Invoke-Sqlcmd",
        "Invoke-Sqlcmd -ServerInstance db -Username sa -Password Is7qQ2xW -Query 'select 1'",
        "Is7qQ2xW",
    ),
    // `New-Object PSCredential('u', (ConvertTo-SecureString 'x' ...))`:
    // the inner group is its own command, found as ConvertTo-SecureString.
    (
        "ConvertTo-SecureString",
        "New-Object System.Management.Automation.PSCredential('dev', (ConvertTo-SecureString 'No7bQ2xW' -AsPlainText -Force))",
        "No7bQ2xW",
    ),
    (
        "Connect-AzAccount",
        "Connect-AzAccount -AccessToken q8ZrT2mVx9LpK4wN -AccountId dev",
        "q8ZrT2mVx9LpK4wN",
    ),
];

/// (entry `tool`, command): prompts, files, references and look-alike flags.
const NEG: &[(&str, &str)] = &[
    ("mysql", "mysql -u root -p shop"),
    ("mysql", "mysql --password -u root"),
    ("mysqlsh", "mysqlsh --uri root@db.test:3306 -p"),
    ("psql", "psql -h db.test -U app -d shop"),
    ("sqlcmd", "sqlcmd -S db.test -E -Q 'select 1'"),
    ("sqlplus", "sqlplus / as sysdba"),
    ("db2", "db2 connect to SAMPLE"),
    (
        "clickhouse-client",
        "clickhouse-client --user default --password --query 'select 1'",
    ),
    ("cqlsh", "cqlsh db.test -u cassandra"),
    ("nodetool", "nodetool -h db.test -p 7199 status"),
    (
        "cypher-shell",
        "cypher-shell -a bolt://db.test:7687 -u neo4j",
    ),
    (
        "neo4j-admin",
        "neo4j-admin dbms set-initial-password --require-password-change",
    ),
    (
        "arangosh",
        "arangosh --server.username root --server.password \"$ARANGO_PW\"",
    ),
    ("influx", "influx bucket list --org acme"),
    (
        "couchbase-cli",
        "cbq -e http://cb.test:8091 -u Administrator",
    ),
    (
        "beeline",
        "beeline -u jdbc:hive2://hive.test:10000 -n admin",
    ),
    ("isql-fb", "isql-fb -user SYSDBA employee.fdb"),
    (
        "snowsql",
        "snowsql -a acme-eu -u svc --authenticator externalbrowser",
    ),
    ("snow", "snow connection test --connection dev"),
    ("usql", "usql postgres://db.test/shop"),
    ("pgcli", "pgcli -h db.test -U app shop"),
    ("mycli", "mycli -u root shop"),
    ("cockroach", "cockroach sql --insecure --host crdb.test"),
    ("pgloader", "pgloader ./load.lisp"),
    (
        "migrate",
        "migrate create -ext sql -dir ./migrations add_users",
    ),
    ("dbmate", "dbmate new add_users"),
    ("atlas", "atlas schema inspect -u env://url"),
    (
        "flyway",
        "flyway -url=jdbc:postgresql://db.test/shop -user=app info",
    ),
    (
        "liquibase",
        "liquibase status --url jdbc:postgresql://db.test/shop",
    ),
    ("sqlx", "sqlx migrate add users"),
    ("prisma", "prisma migrate dev --name init"),
    ("tsql", "tsql -C"),
    (
        "hdbsql",
        "hdbsql -n hana.test:30015 -U KEYNAME 'select 1 from dummy'",
    ),
    ("vsql", "vsql -h v.test -U dbadmin"),
    ("surreal", "surreal start memory"),
    ("redis-cli", "redis-cli -h cache.test -p 6379 ping"),
    ("redis-cli", "redis-cli --askpass -h cache.test"),
    ("mongosh", "mongosh --host db.test -u app -p"),
    (
        "etcdctl",
        "etcdctl --endpoints https://etcd.test:2379 get /config",
    ),
    ("rabbitmqctl", "rabbitmqctl list_users"),
    (
        "rabbitmqadmin",
        "rabbitmqadmin -H mq.test -V /prod list queues",
    ),
    (
        "kafka-console-producer",
        "kafka-console-producer --bootstrap-server k.test:9093 --topic t --producer-property acks=all",
    ),
    (
        "kcat",
        "kcat -b k.test:9093 -X security.protocol=SASL_SSL -L",
    ),
    (
        "mosquitto_pub",
        "mosquitto_pub -h mq.test -p 8883 -t a -m b",
    ),
    (
        "mosquitto_passwd",
        "mosquitto_passwd -c /etc/mosquitto/passwd dev",
    ),
    ("nats", "nats sub --server nats://nats.test:4222 orders"),
    (
        "memtier_benchmark",
        "memtier_benchmark -s cache.test -p 6379",
    ),
    ("redis-server", "redis-server /etc/redis/redis.conf"),
    ("meilisearch", "meilisearch --db-path ./data"),
    ("typesense-server", "typesense-server --data-dir /data"),
    ("elasticsearch-users", "elasticsearch-users list"),
    ("rpk", "rpk cluster info"),
    ("sshpass", "sshpass -f ~/.pw ssh dev@host.test"),
    ("xfreerdp", "xfreerdp /v:host.test /u:admin /cert:ignore"),
    ("rdesktop", "rdesktop -u admin host.test"),
    ("smbclient", "smbclient -L //fs.test -N"),
    (
        "mount",
        "mount -t cifs //fs.test/d /mnt -o credentials=/root/.smbcred,vers=3.0",
    ),
    (
        "sshfs",
        "sshfs -o IdentityFile=~/.ssh/k dev@host.test:/ /mnt",
    ),
    ("lftp", "lftp -u deploy sftp://host.test"),
    ("ncftp", "ncftpput -u dev ftp.test /pub file.txt"),
    ("plink", "plink -ssh -P 2222 dev@host.test uptime"),
    (
        "winscp.com",
        r#"winscp.com /command "open sftp://dev@host.test/" "exit""#,
    ),
    (
        "ipmitool",
        "ipmitool -I lanplus -H bmc.test -U ADMIN -E power status",
    ),
    ("racadm", "racadm getsysinfo"),
    ("snmpwalk", "snmpwalk -v3 -l noAuthNoPriv -u mon 10.0.0.1"),
    ("x11vnc", "x11vnc -rfbauth ~/.vnc/passwd -display :0"),
    ("vncviewer", "vncviewer -passwd ~/.vnc/passwd host.test:1"),
    (
        "VBoxManage",
        "VBoxManage guestcontrol vm1 run --username dev --passwordfile pw.txt -- /bin/ls",
    ),
    ("vmrun", "vmrun -T ws list"),
    (
        "ovftool",
        r#"ovftool vm.ova "vi://admin@vc.test/DC/host/h1""#,
    ),
    ("openstack", "openstack --os-cloud prod server list"),
    (
        "openstack",
        "openstack --os-password <password> server list",
    ),
    ("pvesh", "pvesh get /nodes"),
    (
        "ldapsearch",
        "ldapsearch -x -s sub -a always -b dc=x '(uid=dev)'",
    ),
    (
        "ldapsearch",
        "ldapsearch -x -D cn=admin,dc=x -w <password> -b dc=x",
    ),
    (
        "ldappasswd",
        "ldappasswd -x -D cn=admin,dc=x -W -S uid=dev,dc=x",
    ),
    ("net", r"net use Z: \\fs\share /persistent:yes"),
    ("net", "net user dev /delete"),
    ("net", "net user dev * /add"),
    ("cmdkey", "cmdkey /list"),
    ("schtasks", "schtasks /Query /TN job"),
    ("sc", "sc query svc"),
    ("psexec", r"psexec \\host -s cmd"),
    ("wmic", "wmic process list brief"),
    ("winrs", "winrs -r:host ipconfig"),
    ("usermod", "usermod -aG docker dev"),
    ("htpasswd", "htpasswd -c .htpasswd admin"),
    ("nmcli", "nmcli dev wifi list"),
    ("wpa_passphrase", "wpa_passphrase HomeNet"),
    ("iwctl", "iwctl station wlan0 scan"),
    ("netsh", "netsh wlan show profiles"),
    ("kadmin", "kadmin.local -q listprincs"),
    ("samba-tool", "samba-tool user list"),
    ("netexec", "nxc smb 10.0.0.0/24 --gen-relay-list out.txt"),
    (
        "impacket",
        "GetUserSPNs.py ACME/dev -dc-ip 10.0.0.1 -request",
    ),
    (
        "evil-winrm",
        "evil-winrm -i 10.0.0.5 -c cert.pem -k key.pem -S",
    ),
    ("hydra", "hydra -l admin -P rockyou.txt ssh://10.0.0.5"),
    ("curl", "curl -u admin https://api.test/"),
    ("curl", "curl -sSL https://get.example.test/install.sh"),
    (
        "curl",
        "curl -H 'Accept: application/json' https://api.test/",
    ),
    (
        "curl",
        "curl -H \"Authorization: Bearer $API_TOKEN\" https://api.test/",
    ),
    ("wget", "wget -q https://h.test/f -O out"),
    ("http", "http GET https://api.test/items page==2"),
    ("aria2c", "aria2c -x 8 https://h.test/f"),
    ("lynx", "lynx -dump https://h.test/"),
    ("grpcurl", "grpcurl -plaintext localhost:50051 list"),
    ("websocat", "websocat ws://ws.test/stream"),
    ("ab", "ab -n 100 -c 10 https://h.test/"),
    ("hey", "hey -n 100 -c 10 https://h.test/"),
    (
        "Invoke-WebRequest",
        "Invoke-WebRequest -Uri https://h.test -OutFile out.zip",
    ),
    ("hurl", "hurl --test tests/api.hurl"),
    ("git", "git clone https://git.test/acme/app.git"),
    ("git", "git config --global user.name dev"),
    ("git", "git log -p --stat"),
    ("svn", "svn checkout https://svn.test/trunk --username dev"),
    ("p4", "p4 -u dev -p ssl:p4.test:1666 sync"),
    ("hg", "hg --config ui.username=dev pull"),
    ("cvs", "cvs -d :pserver:dev@cvs.test:/repo login"),
    ("gh", "gh secret set API_KEY < key.txt"),
    (
        "gh",
        "gh api -H 'Accept: application/vnd.github+json' /repos/acme/app",
    ),
    ("glab", "glab variable set ENVIRONMENT production"),
    ("glab", "glab auth login --hostname gl.test --stdin"),
    ("tea", "tea login list"),
    ("gitlab-runner", "gitlab-runner list"),
    ("circleci", "circleci config validate"),
    ("travis", "travis status"),
    ("buildkite-agent", "buildkite-agent pipeline upload"),
    ("drone", "drone secret ls --repo acme/app"),
    ("act", "act -s GITHUB_TOKEN"),
    ("gitea", "gitea admin user list"),
    ("codecov", "codecov -f coverage.xml"),
    ("sentry-cli", "sentry-cli releases list"),
    ("snyk", "snyk test --org acme"),
    ("fossa", "fossa analyze"),
    ("postman", "postman collection run c.json"),
    ("bru", "bru run --env prod"),
    (
        "jenkins-cli",
        "jenkins-cli -s https://ci.test/ -auth @creds.txt build job",
    ),
    ("docker", "docker run -p 8080:80 -e LOG_LEVEL=debug nginx"),
    ("docker", "docker login -u ci --password-stdin reg.test"),
    ("docker-compose", "docker-compose up -d"),
    ("skopeo", "skopeo inspect docker://reg.test/app:1"),
    ("crane", "crane digest reg.test/app:1"),
    ("helm", "helm install api ./chart --set image.tag=1.2.3"),
    (
        "helm",
        "helm install api ./chart --set auth.existingSecret=db-creds --set auth.secretKeys.passwordKey=password",
    ),
    (
        "helmfile",
        "helmfile apply --state-values-set image.tag=1.2.3",
    ),
    (
        "kubectl",
        "kubectl create secret generic db --from-file=password=./pw.txt",
    ),
    ("kubectl", "kubectl get pods -o wide"),
    ("kustomize", "kustomize build overlays/prod"),
    ("argocd", "argocd app list"),
    ("argo", "argo list -n workflows"),
    ("flux", "flux get kustomizations"),
    ("rancher", "rancher context switch"),
    ("kubeadm", "kubeadm token list"),
    ("k3s", "k3s kubectl get nodes"),
    ("ctr", "ctr images ls"),
    ("crictl", "crictl ps -a"),
    ("trivy", "trivy image alpine:3.20"),
    ("cosign", "cosign verify --key cosign.pub reg.test/app:1"),
    ("az", "az login --use-device-code"),
    (
        "az",
        "az storage blob list --account-name x --auth-mode login",
    ),
    ("aws", "aws configure set region eu-west-1"),
    ("aws", "aws secretsmanager get-secret-value --secret-id x"),
    ("gcloud", "gcloud sql users list --instance=db1"),
    ("doctl", "doctl compute droplet list"),
    ("linode-cli", "linode-cli linodes list"),
    ("flyctl", "flyctl secrets set LOG_LEVEL=debug"),
    ("flyctl", "fly deploy"),
    ("heroku", "heroku config:set NODE_ENV=production -a app"),
    ("vercel", "vercel env add API_TOKEN production"),
    ("netlify", "netlify deploy --prod"),
    ("supabase", "supabase start"),
    ("azcopy", "azcopy login --tenant-id t"),
    (
        "rclone",
        "rclone config create s3r s3 provider AWS region eu-west-1",
    ),
    ("rclone", "rclone copy s3r:bucket ./out"),
    ("s3cmd", "s3cmd ls s3://bucket"),
    ("mc", "mc alias list"),
    (
        "gsutil",
        r#"gsutil -o "GSUtil:parallel_composite_upload_threshold=150M" cp f gs://b"#,
    ),
    ("databricks", "databricks fs ls dbfs:/ --profile prod"),
    ("terraform", "terraform apply -var region=eu-west-1"),
    ("pulumi", "pulumi config set aws:region us-east-1"),
    ("ansible", "ansible-playbook site.yml -e env=prod"),
    ("ibmcloud", "ibmcloud login --sso"),
    ("scw", "scw instance server list"),
    ("civo", "civo apikey list"),
    ("aliyun", "aliyun ecs DescribeInstances"),
    ("cf", "cf login -a https://api.cf.test --sso"),
    ("ngrok", "ngrok http 8080"),
    ("cloudflared", "cloudflared tunnel list"),
    ("tailscale", "tailscale status"),
    ("mitmproxy", "mitmdump -p 8081"),
    ("pscale", "pscale auth login"),
    ("neonctl", "neonctl auth"),
    (
        "stripe",
        "stripe listen --forward-to localhost:3000/webhook",
    ),
    ("auth0", "auth0 apps list"),
    ("vault", "vault login -method=oidc"),
    ("vault", "vault kv get secret/app"),
    ("consul", "consul kv put service/web/port 8080"),
    ("nomad", "nomad job status api"),
    (
        "boundary",
        "boundary authenticate password -login-name dev -password=file:///run/secrets/boundary",
    ),
    ("bw", "bw unlock --passwordenv BW_PASSWORD"),
    ("bw", "bw login dev@example.test"),
    ("bws", "bws secret list"),
    ("doppler", "doppler secrets get DB_PASSWORD --plain"),
    ("infisical", "infisical secrets get API_KEY"),
    ("chamber", "chamber read api db_password"),
    ("akeyless", "akeyless list-items"),
    ("conjur", "conjur whoami"),
    (
        "ansible-vault",
        "ansible-vault encrypt_string --vault-password-file ~/.vp --stdin-name db_password",
    ),
    (
        "openssl",
        "openssl rsa -in k.pem -passin env:KEY_PW -out p.pem",
    ),
    ("openssl", "openssl passwd -6 -stdin"),
    ("keytool", "keytool -list -keystore k.jks"),
    ("jarsigner", "jarsigner -verify app.jar"),
    (
        "apksigner",
        "apksigner sign --ks k.jks --ks-pass env:KS_PASS app.apk",
    ),
    ("signtool", "signtool verify /pa app.exe"),
    (
        "codesign",
        "security find-generic-password -a dev -s api -w",
    ),
    (
        "codesign",
        "xcrun notarytool submit app.zip -p AC_NOTARY --wait",
    ),
    (
        "altool",
        "xcrun altool --validate-app -f app.ipa --apiKey KEYID --apiIssuer ISSUER",
    ),
    ("certutil", "certutil -hashfile f.zip SHA256"),
    ("pk12util", "pk12util -l c.p12"),
    ("gpg", "gpg --batch --passphrase-file pw.txt -d f.gpg"),
    ("ssh-keygen", "ssh-keygen -t ed25519 -N '' -f k"),
    ("zip", "zip -r out.zip dir"),
    ("unzip", "unzip -o in.zip -d out"),
    ("7z", "7z x -p a.7z"),
    ("rar", "unrar x a.rar"),
    ("pdftk", "pdftk in.pdf cat 1-5 output out.pdf"),
    ("veracrypt", "veracrypt --text --list"),
    ("restic", "restic -r /srv/restic snapshots"),
    ("kopia", "kopia snapshot list"),
    ("certbot", "certbot renew --dry-run"),
    ("pkcs11-tool", "pkcs11-tool --list-slots"),
    ("ykman", "ykman info"),
    ("yubico-piv-tool", "yubico-piv-tool -a status"),
    ("mkpasswd", "mkpasswd -m sha-512"),
    ("caddy", "caddy run --config Caddyfile"),
    ("npm", "npm config set registry https://registry.npmjs.org/"),
    ("npm", "npm publish --otp 123456"),
    ("yarn", "yarn config set nodeLinker node-modules"),
    ("twine", "twine upload --repository testpypi dist/*"),
    ("uv", "uv publish --trusted-publishing always"),
    ("pip", "pip install -i https://pypi.org/simple x"),
    ("poetry", "poetry config virtualenvs.in-project true"),
    ("bundle", "bundle config set --local path vendor/bundle"),
    ("cargo", "cargo login --registry acme"),
    ("dotnet", "dotnet run -p ./src/App.csproj"),
    ("nuget", "nuget restore App.sln"),
    ("mvn", "mvn -DskipTests package"),
    ("gradle", "./gradlew build -Pversion=1.2.0"),
    ("java", "java -Dserver.port=8081 -jar app.jar"),
    ("composer", "composer config minimum-stability dev"),
    ("jfrog", "jf rt ping --url https://a.test"),
    ("sonar-scanner", "sonar-scanner -Dsonar.projectKey=app"),
    ("flutter", "flutter build apk --dart-define=FLAVOR=prod"),
    (
        "newman",
        "newman run c.json --env-var baseUrl=https://api.test",
    ),
    ("conan", "conan remote list"),
    ("hatch", "hatch build"),
    ("pdm", "pdm publish --repository testpypi"),
    ("maturin", "maturin build --release"),
    ("ant", "ant -Dbuild.dir=out release"),
    ("hadoop", "hdfs dfs -ls /"),
    (
        "spark-submit",
        "spark-submit --conf spark.executor.memory=4g app.py",
    ),
    ("choco", "choco install git -y"),
    ("Publish-Module", "Publish-Module -Name Acme -WhatIf"),
    (
        "ansible-galaxy",
        "ansible-galaxy collection install community.general",
    ),
    ("wp", "wp plugin list"),
    ("drush", "drush cr"),
    ("swaks", "swaks --to a@example.test --server smtp.test"),
    ("msmtp", "msmtp --read-envelope-from -t"),
    ("kcadm.sh", "kcadm.sh get realms"),
    ("kc.sh", "kc.sh start-dev"),
    ("grafana-cli", "grafana-cli plugins ls"),
    ("logcli", "logcli query '{app=\"api\"}'"),
    ("huggingface-cli", "huggingface-cli whoami"),
    ("wandb", "wandb login --relogin"),
    ("dvc", "dvc remote modify storage url s3://bucket/path"),
    ("jupyter", "jupyter lab --no-browser --port 8888"),
    ("airflow", "airflow users list"),
    ("superset", "superset db upgrade"),
    ("strapi", "strapi develop"),
    ("directus", "directus bootstrap"),
    (
        "ConvertTo-SecureString",
        "ConvertTo-SecureString -String $env:PW -AsPlainText -Force",
    ),
    ("New-LocalUser", "New-LocalUser -Name dev -NoPassword"),
    (
        "Invoke-Sqlcmd",
        "Invoke-Sqlcmd -ServerInstance db -Query 'select 1'",
    ),
    ("Connect-AzAccount", "Connect-AzAccount -Identity"),
];

fn spec() -> &'static Spec {
    static S: std::sync::OnceLock<Spec> = std::sync::OnceLock::new();
    S.get_or_init(|| Spec::embedded().expect("embedded spec"))
}

fn scan(cmd: &str) -> Vec<Candidate<'static>> {
    static A: std::sync::OnceLock<ShellAnalyzer<'static>> = std::sync::OnceLock::new();
    let a = A.get_or_init(|| ShellAnalyzer::new(spec()).expect("shell analyzer"));
    let mut out = Vec::new();
    a.analyze(&Routed::raw_text(cmd, Route::Command), &mut out);
    out
}

#[test]
fn positives() {
    let mut fails = Vec::new();
    for &(tool, cmd, secret) in POS {
        let out = scan(cmd);
        let got: Vec<(&str, Option<&str>)> = out
            .iter()
            .map(|c| (c.secret.expose(), c.context.tool.as_deref()))
            .collect();
        let hit = got.iter().any(|&(s, t)| s == secret && t == Some(tool));
        let stray = got.iter().any(|&(s, _)| s != secret);
        if !hit || stray {
            fails.push(format!("{tool}: {cmd}\n    got {got:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn negatives() {
    let mut fails = Vec::new();
    for &(tool, cmd) in NEG {
        let out = scan(cmd);
        if !out.is_empty() {
            let got: Vec<_> = out
                .iter()
                .map(|c| (c.secret.expose(), c.context.tool.as_deref()))
                .collect();
            fails.push(format!("{tool}: {cmd}\n    got {got:?}"));
        }
    }
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// Every entry with a credential argument has a positive and a negative
/// example, and every example names an existing entry.
#[test]
fn every_entry_has_examples() {
    let spec = spec();
    let names: Vec<&str> = spec.cli_tools.iter().map(|t| t.tool.as_str()).collect();
    for &(t, _, _) in POS {
        assert!(names.contains(&t), "POS names unknown entry {t}");
    }
    for &(t, _) in NEG {
        assert!(names.contains(&t), "NEG names unknown entry {t}");
    }
    let mut missing = Vec::new();
    for tool in &spec.cli_tools {
        let credential = tool.args.iter().any(|a| {
            a.pattern.is_some()
                || (!matches!(a.form, None | Some(ArgForm::None))
                    && a.kind.as_ref() != Some(&ArgKind::None))
        });
        if !credential {
            continue;
        }
        let t = tool.tool.as_str();
        if !POS.iter().any(|p| p.0 == t) {
            missing.push(format!("{t}: no positive example"));
        }
        if !NEG.iter().any(|n| n.0 == t) {
            missing.push(format!("{t}: no negative example"));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}
