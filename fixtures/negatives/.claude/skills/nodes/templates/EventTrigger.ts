async function connect(
	_credentials: ICredentialDataDecryptedObject,
): Promise<Client> {
	const secret = existing.secretsProcessed;
	const tokenHash = secrets.uploadTokenHash;
	return { secret: (&SecretRaw{}).Schema().Required(), token: "={{$credentials.token}}" };
}
