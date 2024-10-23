# Open Authorizer Lambda

This AWS Lambda function is designed as an Authorization Layer to protect sensitive API routes by verifying user
identity through JWT (JSON Web Tokens) and confirming user existence in DynamoDB. It’s a critical component for ensuring
only authenticated users can access your API resources, enhancing security and reliability. Here’s an overview of its
key features:

## Key Highlights

- **JWT-Based Authentication**:
  The function uses JWT tokens to verify the identity of users trying to access the API. By decoding and verifying the
  token, it ensures only users with valid credentials can proceed.

- **DynamoDB User Verification**:
  Beyond just checking the token, the function queries DynamoDB to confirm the user’s existence in the database. This
  double verification adds an extra layer of security, ensuring that users not only have valid tokens but are also
  registered in the system.

- **Dynamic IAM Policy Generation**:
  Based on the verification results, the function generates an IAM policy that either allows or denies the user access
  to the requested API resource. This dynamic policy generation gives fine-grained control over who can access specific
  API methods.

## How It Works

- **Token Extraction**:
  The function pulls the JWT token from the Authorization header in the incoming request. It checks that the token
  follows the Bearer scheme, ensuring the token format is valid.

- **JWT Verification**:
  Using the secret stored in JWT_SECRET, the function verifies the token to decode the user's identity. If the token is
  invalid or missing, access is immediately denied.

- **DynamoDB Scan for User Existence**:
  Once the token is verified, the function performs a DynamoDB scan to confirm that the user (based on the id from the
  token) exists in the database. If no user is found, the function denies access.

- **Allow/Deny Policy Generation**:
  If both the token and user checks pass, the function generates a policy that allows the user to access the requested
  resource. Otherwise, it returns a denial policy, blocking access.

## Why This Lambda is Awesome

This Lambda function provides robust, scalable API security by leveraging both JWT authentication and DynamoDB user
validation. It dynamically enforces access control based on real-time user data, ensuring that only verified users can
interact with your API. The serverless architecture ensures that the function scales effortlessly as your user base
grows, while the use of IAM policies ensures security is maintained at the API level.













