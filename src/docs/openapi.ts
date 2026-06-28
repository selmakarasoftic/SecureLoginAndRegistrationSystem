import { OpenAPIV3 } from "openapi-types";

export const openApiSpec: OpenAPIV3.Document = {
  openapi: "3.0.3",
  info: {
    title: "SSD API",
    version: "1.0.0",
    description: "API documentation for authentication system (Selma version).",
  },
  servers: [
    {
      url: "http://localhost:3000/api",
      description: "Local development server",
    },
  ],
  tags: [
    {
      name: "Health",
      description: "Server health check",
    },
    {
      name: "Auth",
      description: "Authentication endpoints",
    },
    {
      name: "Configuration",
      description: "Public configuration used by frontend",
    },
    {
      name: "SSO",
      description: "Single Sign-On endpoints for Google and GitHub",
    },
    {
      name: "Session Management",
      description: "JWT access/refresh token session endpoints",
    },
  ],
  paths: {
    "/health": {
      get: {
        tags: ["Health"],
        summary: "Health check",
        operationId: "healthCheck",
        responses: {
          "200": {
            description: "Server is running",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    status: {
                      type: "string",
                      example: "ok",
                    },
                  },
                },
                example: {
                  status: "ok",
                },
              },
            },
          },
        },
      },
    },

    "/public-config": {
      get: {
        tags: ["Configuration"],
        summary: "Get public frontend configuration",
        operationId: "getPublicConfig",
        description:
          "Returns public configuration values needed by the frontend, such as the hCaptcha site key.",
        responses: {
          "200": {
            description: "Public configuration returned successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    hCaptchaSiteKey: {
                      type: "string",
                      example: "10000000-ffff-ffff-ffff-000000000001",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },

    "/register": {
      post: {
        tags: ["Auth"],
        summary: "Register user",
        operationId: "registerUser",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  fullName: {
                    type: "string",
                    example: "Selma Karasoftić",
                    minLength: 3,
                  },
                  email: {
                    type: "string",
                    format: "email",
                    example: "test@gmail.com",
                  },
                  username: {
                    type: "string",
                    example: "test123",
                    minLength: 3,
                    maxLength: 20,
                  },
                  password: {
                    type: "string",
                    example: "Test123!",
                    minLength: 6,
                  },
                  phone: {
                    type: "string",
                    example: "061234567",
                  },
                },
                required: [
                  "fullName",
                  "email",
                  "username",
                  "password",
                  "phone",
                ],
              },
              example: {
                fullName: "Selma Karasoftić",
                email: "test@gmail.com",
                username: "test123",
                password: "Test123!",
                phone: "061234567",
              },
            },
          },
        },
        responses: {
          "201": {
            description: "User registered successfully",
            content: {
              "application/json": {
                example: {
                  message:
                    "User registered successfully. Please verify your email before login.",
                },
              },
            },
          },
          "400": {
            description: "Validation error",
            content: {
              "application/json": {
                example: {
                  message: "All fields are required",
                },
              },
            },
          },
        },
      },
    },

    "/login": {
      post: {
        tags: ["Auth"],
        summary: "Login user with hCaptcha protection",
        operationId: "loginUser",
        description:
          "Validates hCaptcha first, then checks user credentials. If credentials are correct, the user continues to 2FA setup or 2FA verification.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  usernameOrEmail: {
                    type: "string",
                    example: "test123",
                  },
                  password: {
                    type: "string",
                    example: "Test123!",
                  },
                  captchaToken: {
                    type: "string",
                    example: "hcaptcha-response-token",
                  },
                },
                required: ["usernameOrEmail", "password", "captchaToken"],
              },
              example: {
                usernameOrEmail: "test123",
                password: "Test123!",
                captchaToken: "hcaptcha-response-token",
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Credentials are correct and 2FA is required",
            content: {
              "application/json": {
                examples: {
                  requiresTwoFactor: {
                    value: {
                      message:
                        "Credentials are correct. Two-factor verification is required.",
                      nextStep:
                        "Verify the configured 2FA method or use a recovery code.",
                      requiresTwoFactor: true,
                      userId: 5,
                      twoFactorMethod: "email",
                    },
                  },
                  requiresTwoFactorSetup: {
                    value: {
                      message:
                        "Credentials are correct. User must set up 2FA before accessing the system.",
                      nextStep: "Choose one method: email, sms, or totp.",
                      requiresTwoFactorSetup: true,
                      userId: 5,
                    },
                  },
                },
              },
            },
          },
          "400": {
            description: "Missing fields or captcha verification failed",
            content: {
              "application/json": {
                example: {
                  message: "Captcha verification failed",
                },
              },
            },
          },
          "401": {
            description: "Invalid credentials",
            content: {
              "application/json": {
                example: {
                  message: "Invalid credentials",
                },
              },
            },
          },
          "404": {
            description: "User does not exist",
            content: {
              "application/json": {
                example: {
                  message: "User does not exist",
                },
              },
            },
          },
        },
      },
    },

    "/google-login": {
      get: {
        tags: ["SSO"],
        summary: "Start Google SSO login",
        operationId: "startGoogleSso",
        description:
          "Generates a Google OAuth authorization URL and returns it to the frontend.",
        responses: {
          "200": {
            description: "Google authorization URL generated successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    authUrl: {
                      type: "string",
                      example:
                        "https://accounts.google.com/o/oauth2/v2/auth?...",
                    },
                  },
                },
              },
            },
          },
          "500": {
            description: "Google SSO is not configured properly",
            content: {
              "application/json": {
                example: {
                  message: "Google SSO is not configured properly.",
                },
              },
            },
          },
        },
      },
    },

    "/google-callback": {
      get: {
        tags: ["SSO"],
        summary: "Handle Google OAuth callback",
        operationId: "handleGoogleCallback",
        description:
          "Receives the authorization code from Google, validates the state parameter, extracts user information, and redirects back to the frontend flow.",
        parameters: [
          {
            name: "code",
            in: "query",
            required: true,
            schema: {
              type: "string",
            },
            description: "Temporary authorization code returned by Google",
          },
          {
            name: "state",
            in: "query",
            required: true,
            schema: {
              type: "string",
            },
            description: "CSRF protection state value",
          },
        ],
        responses: {
          "302": {
            description:
              "Redirects to frontend with SSO result such as requires_2fa, requires_2fa_setup, complete_registration, or error.",
          },
        },
      },
    },

    "/github-login": {
      get: {
        tags: ["SSO"],
        summary: "Start GitHub SSO login",
        operationId: "startGithubSso",
        description:
          "Generates a GitHub OAuth authorization URL and returns it to the frontend.",
        responses: {
          "200": {
            description: "GitHub authorization URL generated successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    authUrl: {
                      type: "string",
                      example:
                        "https://github.com/login/oauth/authorize?...",
                    },
                  },
                },
              },
            },
          },
          "500": {
            description: "GitHub SSO is not configured properly",
            content: {
              "application/json": {
                example: {
                  message: "GitHub SSO is not configured properly.",
                },
              },
            },
          },
        },
      },
    },

    "/github-callback": {
      get: {
        tags: ["SSO"],
        summary: "Handle GitHub OAuth callback",
        operationId: "handleGithubCallback",
        description:
          "Receives the authorization code from GitHub, validates the state parameter, exchanges the code for an access token, extracts user information, and redirects back to the frontend flow.",
        parameters: [
          {
            name: "code",
            in: "query",
            required: true,
            schema: {
              type: "string",
            },
            description: "Temporary authorization code returned by GitHub",
          },
          {
            name: "state",
            in: "query",
            required: true,
            schema: {
              type: "string",
            },
            description: "CSRF protection state value",
          },
        ],
        responses: {
          "302": {
            description:
              "Redirects to frontend with SSO result such as requires_2fa, requires_2fa_setup, complete_registration, or error.",
          },
        },
      },
    },

    "/refresh": {
      post: {
        tags: ["Session Management"],
        summary: "Refresh access token",
        operationId: "refreshToken",
        description:
          "Uses the active refresh token from the httpOnly cookie to generate a new access token and rotate the refresh token. The old refresh token is revoked and linked to the new one using replaced_by.",
        responses: {
          "200": {
            description: "Token refreshed successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    message: {
                      type: "string",
                      example: "Token refreshed successfully",
                    },
                    accessToken: {
                      type: "string",
                      example:
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    },
                  },
                },
              },
            },
          },
          "401": {
            description:
              "Refresh token is missing, invalid, expired, or revoked",
            content: {
              "application/json": {
                example: {
                  message: "Refresh token is missing",
                },
              },
            },
          },
          "404": {
            description: "User not found",
            content: {
              "application/json": {
                example: {
                  message: "User not found",
                },
              },
            },
          },
          "500": {
            description: "Could not refresh token",
            content: {
              "application/json": {
                example: {
                  message: "Could not refresh token",
                },
              },
            },
          },
        },
      },
    },

    "/logout": {
      post: {
        tags: ["Session Management"],
        summary: "Logout user",
        operationId: "logoutUser",
        description:
          "Revokes the active refresh token in the database and clears both access and refresh cookies.",
        responses: {
          "200": {
            description: "User logged out successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    message: {
                      type: "string",
                      example:
                        "Logged out successfully. Refresh token revoked.",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },

    "/me": {
      get: {
        tags: ["Session Management"],
        summary: "Get authenticated user",
        operationId: "getAuthenticatedUser",
        description:
          "Protected route that reads the access token from the httpOnly cookie, verifies it, and returns the authenticated user payload.",
        responses: {
          "200": {
            description: "Authenticated user returned successfully",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    message: {
                      type: "string",
                      example: "Authenticated user loaded successfully.",
                    },
                    user: {
                      type: "object",
                      properties: {
                        sub: {
                          type: "number",
                          example: 5,
                        },
                        username: {
                          type: "string",
                          example: "testuser",
                        },
                        email: {
                          type: "string",
                          example: "test@example.com",
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          "401": {
            description:
              "User is not authenticated or access token is invalid/expired",
            content: {
              "application/json": {
                examples: {
                  notAuthenticated: {
                    value: {
                      error: "not_authenticated",
                    },
                  },
                  tokenExpired: {
                    value: {
                      error: "token_expired",
                    },
                  },
                  invalidToken: {
                    value: {
                      error: "invalid_token",
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
};