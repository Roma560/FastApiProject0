
# FastAPI Psychic Readings Project Instructions

## Project Overview
This is a FastAPI project for a psychic/astrological consultations platform with user authentication, psychic profiles, chat functionality, and WebSocket support.

## Key Features
- User registration and authentication (JWT tokens)
- Role-based access (client/admin)
- Psychic profile management
- Chat system with real-time messaging
- WebSocket support for live communication
- SQLite database with async SQLAlchemy
- Configuration management with environment variables
- Proper logging system
- Optimized database models with indexes

## Development Setup

### Environment Setup
```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env file with your settings

# Initialize database
python init_db.py

# Run development server
uvicorn main:app --reload
```

### Environment Variables
Create a `.env` file based on `.env.example`:
- `SECRET_KEY`: JWT secret key (IMPORTANT: Change in production!)
- `DATABASE_URL`: Database connection string
- `DEBUG`: Enable/disable debug mode
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT token expiration time

## Project Structure
- `main.py` - Main FastAPI application with all endpoints
- `models.py` - SQLAlchemy database models with optimized indexes
- `schemas.py` - Pydantic schemas for request/response validation
- `auth.py` - Authentication utilities (JWT, password hashing)
- `database.py` - Database configuration and session management
- `config.py` - Configuration management using pydantic-settings
- `logger.py` - Centralized logging configuration
- `init_db.py` - Database initialization script
- `websocket_manager.py` - WebSocket connection management with proper logging
- `websocket_test.html` - WebSocket testing interface
- `requirements.txt` - Project dependencies
- `.env.example` - Environment variables template
- `test.db` - SQLite database file

## Database Models
- `User` - User accounts with roles (client/admin)
- `PsychicProfile` - Psychic consultant profiles
- `Chat` - Chat conversations between users and psychics
- `Message` - Individual messages in chats
- `MessageStatus` - Message read status tracking

## Key Endpoints
- `POST /register` - User registration
- `POST /login` - User authentication
- `GET /users` - Get user list (admin only)
- `POST /psychics` - Create psychic profile (admin only)
- `GET /psychics` - Get all psychic profiles
- `PUT /psychics/{profile_id}` - Update psychic profile (admin only)
- `DELETE /psychics/{profile_id}` - Delete psychic profile (admin only)
- `POST /chats` - Create new chat
- `GET /chats` - Get user's chats
- `GET /chats/{chat_id}/messages` - Get chat messages (admin only)
- `POST /chats/{chat_id}/messages` - Send message
- `PUT /messages/{message_id}/status` - Update message status
- `WebSocket /ws/{user_id}` - WebSocket connection for real-time messaging

## Authentication
- Uses JWT tokens with Bearer authentication
- Passwords are hashed with bcrypt
- Role-based access control (admin/client)
- Configurable token expiration

## Testing
- Use Swagger UI at http://127.0.0.1:8000/docs
- Test WebSocket functionality with `websocket_test.html`
- Use `test_main.http` for HTTP endpoint testing

## Configuration Management
- Environment-based configuration using pydantic-settings
- Centralized config in `config.py`
- Support for `.env` files
- Type-safe configuration with validation

## Logging
- Centralized logging configuration in `logger.py`
- Configurable log levels
- Structured logging for debugging
- No print statements in production code

## Security Features
- Environment-based secret management
- Password hashing with bcrypt
- JWT token authentication
- Role-based access control
- Input validation via Pydantic schemas
- Proper error handling

## Database Optimizations
- Added proper field lengths and constraints
- Database indexes for frequently queried fields
- Composite indexes for complex queries
- Boolean fields instead of integers where appropriate
- Text fields for long content

## Common Tasks

### Adding New Endpoints
1. Add route handler to `main.py`
2. Create request/response schemas in `schemas.py` if needed
3. Add database models to `models.py` if needed
4. Update CLAUDE.md documentation
5. Test via Swagger UI

### Database Changes
1. Modify models in `models.py`
2. Delete `test.db` file
3. Run `python init_db.py` to recreate database
4. Update schemas in `schemas.py` if needed

### WebSocket Features
- Connection management handled by `websocket_manager.py`
- Real-time messaging between users
- Connection tracking by user ID
- Proper error handling and logging
- Automatic cleanup of disconnected connections

### Environment Configuration
1. Copy `.env.example` to `.env`
2. Modify values as needed
3. Restart application to load new configuration

## Production Deployment Notes
- Set strong `SECRET_KEY` in production
- Use PostgreSQL instead of SQLite for production
- Set appropriate log levels
- Configure CORS properly
- Use environment variables for all sensitive data

## Current Branch
Working on branch: `second`

## Development Notes
- Project uses async/await patterns throughout
- SQLite database for development (easily replaceable)
- Russian language used in README and some comments
- WebSocket support for real-time features
- Comprehensive error handling and logging
- Type hints throughout the codebase