import {DynamoDBClient, GetItemCommand} from "@aws-sdk/client-dynamodb";
import jwt from 'jsonwebtoken';

const region = 'us-east-2'

const dynamoDbClient = new DynamoDBClient({region});

const DYNAMO_TABLE_NAME = 'ProjectOpen';
const JWT_SECRET = process.env.JWT_SECRET;

export const handler = async (event) => {
    try {
        console.log(event)
        const token = getTokenFromHeader(event);

        if (!token) {
            return generatePolicy('Deny', event.methodArn);
        }

        try {
            // Verify the token
            const decoded = jwt.verify(token, JWT_SECRET);
            console.log(decoded)

            const getParams = {
                TableName: DYNAMO_TABLE_NAME,
                Key: {email: {S: decoded.email.S}},
            };

            const existingUser = await dynamoDbClient.send(new GetItemCommand(getParams));
            console.log("existingUser", existingUser)
            if (!existingUser.Item) {
                return generatePolicy('Deny', event.methodArn);
            }

            const user = {
                id: existingUser.Item.id.S,
                name: existingUser.Item.name.S,
                email: existingUser.Item.email.S,
                address: existingUser.Item.address.S,
                imageUrl: existingUser.Item.imageUrl.S,
                createdOn: existingUser.Item.createdOn.S,
            };

            // Generate the policy to allow access
            return generatePolicy('Allow', event.methodArn, user);
        } catch (err) {
            // Token is invalid
            console.log(err)
            return generatePolicy('Deny', event.methodArn);
        }
    } catch (error) {
        console.error('Error authorization user:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({message: 'Internal Server Error Authorization'}),
        };
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