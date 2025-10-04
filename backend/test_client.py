from jose import jwt

# Your JWT token
token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiM2ViZDZkZi0zZWQ0LTRkNzctODljZS1mNTkwNTRjYjFhN2EiLCJyb2xlIjoicmVzdGF1cmFudCIsImV4cCI6MTc1OTU2NTg3OSwidHlwZSI6ImFjY2VzcyJ9.98WBkcDfJNCSEasOkM8At8BaZSZcRj5Etw9eUNLUGT2-WVPjFfV4tXKzhnoD34nZdYZfoajPtBsOksqcLudoKg"

# Your secret key (use the same one that was used to encode the JWT)
secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

# Decode the JWT token
try:
    decoded_payload = jwt.decode(token, secret_key, algorithms=["HS512"])
    print(decoded_payload)
except Exception as e:
    print(f"Error decoding token: {e}")
