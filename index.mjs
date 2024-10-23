import {DynamoDBClient, ScanCommand} from "@aws-sdk/client-dynamodb";
import jwt from 'jsonwebtoken';

const region = process.env.AWS_REGION;

const dynamoDbClient = new DynamoDBClient({region});

const DYNAMO_TABLE_NAME = process.env.DYNAMO_TABLE_NAME;
const JWT_SECRET = process.env.JWT_SECRET;

export const handler = async (event) => {
    try {
        console.log(event)
        const token = getTokenFromHeader(event);

        if (!token) {
            console.log('Deny', event.methodArn, "!token")
            return generatePolicy('Deny', event.methodArn);
        }

        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log(decoded)

        const scanParams = {
            TableName: DYNAMO_TABLE_NAME,
            FilterExpression: '#n = :id',
            ExpressionAttributeNames: {
                '#n': 'id'
            },
            ExpressionAttributeValues: {
                ':id': {S: decoded.id}
            }
        };

        const data = await dynamoDbClient.send(new ScanCommand(scanParams));
        console.log(data)
        if (data.Count === 0) {
            console.log('Deny', event.methodArn, "ScanCommand")
            return generatePolicy('Deny', event.methodArn);
        }

        const existingUser = data.Items[0]
        const user = {
            id: existingUser.id.S,
            name: existingUser.name.S,
            email: existingUser.email.S,
            address: existingUser.address.S,
            imageUrl: existingUser.imageUrl.S,
            password: existingUser.password.S,
            createdOn: existingUser.createdOn.S,
        };

        // Generate the policy to allow access
        console.log('Allow', event.methodArn, user)
        return generatePolicy('Allow', event.methodArn, user);
    } catch (err) {
        // Token is invalid
        console.log('Deny', event.methodArn, err)
        return generatePolicy('Deny', event.methodArn);
    }
};

// Helper function to extract the token from the Authorization header
function getTokenFromHeader(event) {
    const authorizationHeader = event.authorizationToken;
    if (!authorizationHeader) {
        return null;
    }

    const [scheme, token] = authorizationHeader.split(' ');

    // Ensure it’s a Bearer token
    if (scheme !== 'Bearer' || !token) {
        return null;
    }

    return token;
}

// Helper function to generate an IAM policy
function generatePolicy(effect, resource, user) {
    console.log(effect, resource, user)
    return {
        principalId: user ? user.id : 'anonymous',  // principalId can be set to the user's ID from the token
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: effect,
                    Resource: resource
                }
            ]
        },
        context: user || {}
    };
}