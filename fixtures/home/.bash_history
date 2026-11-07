ls -la
sshpass -p Hist0rySsh1 ssh root@203.0.113.50
export DB_PASS=$(vault kv get -field=pw secret/app)
mysql -u root -p
