import swaggerJsdoc from 'swagger-jsdoc';
import { port } from './env.js';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Fleet Management API',
      version: '1.0.0',
      description: 'Authentication, role management, and fleet access control APIs',
    },
    servers: [{ url: `http://localhost:${port}`, description: 'Local server' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        cookieAuth: { type: 'apiKey', in: 'cookie', name: 'authToken' },
      },
      schemas: {
        Account: {
          type: 'object',
          properties: {
            id: { type: 'string' }, name: { type: 'string', minLength: 6, maxLength: 20 }, email: { type: 'string', format: 'email' }, phone: { type: 'string' },
            role: { type: 'string', enum: ['super_admin', 'admin', 'operator'] },
            depotIds: { type: 'array', items: { type: 'string' } }, active: { type: 'boolean' },
          },
        },
        AuthResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean' }, data: { $ref: '#/components/schemas/Account' },
          },
        },
        AccountInput: {
          type: 'object',
          required: ['name', 'email', 'role'],
          properties: {
            name: { type: 'string', minLength: 6, maxLength: 20 }, email: { type: 'string', format: 'email' }, phone: { type: 'string' },
            role: { type: 'string', enum: ['super_admin', 'admin', 'operator'] },
            depotIds: { type: 'array', description: 'Multiple depot IDs are supported. Admin accounts default to ["*"] (all depots) when omitted.', items: { type: 'string' } },
          },
        },
        Error: {
          type: 'object',
          properties: { success: { type: 'boolean', example: false }, message: { type: 'string' } },
        },
      },
    },
  },
  apis: ['./src/routes/*.js'],
};

export default swaggerJsdoc(options);
