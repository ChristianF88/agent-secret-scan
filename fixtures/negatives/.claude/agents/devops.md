---
name: devops
---
```yaml
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: url
auth:
  type: http
---
apiVersion: v1
kind: Secret
data:
  username: YWRtaW4=  # base64 encoded
  password: cGFzc3dvcmQ=
```

```python
def login(email: str, password: str = Field(min_length=8)):
    """
    Args:
        password: User's password (will be hashed)
    Raises:
        InvalidCredentialsError: When credentials are invalid
    """
```
