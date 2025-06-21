# Vue.js Frontend Application Development Prompt

You are an expert Vue.js developer tasked with building a modern, production-ready frontend application. Please create a complete, well-structured application following Vue.js and TypeScript best practices.

## Tech Stack Requirements

**Core Technologies:**
- Vue.js 3 (Composition API)
- TypeScript (strict mode)
- Vuetify 3 (Material Design components)
- Pinia (state management)
- Axios (HTTP client)
- Vue Router 4

**Additional Tools:**
- Vite (build tool)
- ESLint + Prettier (code quality)
- Vitest (testing framework)

## Project Requirements

### Application Overview

This will be sceleton application, a framework to build addition functionality into.
The framework should provide functional user authentication.

### Core Features
The initial functionality should be:
- Header with application title, and user drop down menu which allows (depending on the authentication state):
    - Register
    - Login
    - Logout
    - Profile Update
    - Password Chanage
    - Password Reset
- Footer where various status information can be displayed.
- Sidebar used to access future functionalities (sidebar menu)

### API Integration
The user authentication will be provided by out go-auth/auth-service. There is swagger.json and swagger.yaml with openapi definition.


### UI/UX Requirements

- Theme: Dark/Light mode toggle
- Layout: Sidebar navigation with main content area
- Responsive design for mobile and desktop
- Loading states and error handling
- All notifications via snackbar (the standard vue way)
- Confirmation dialogs for destructive actions

## Development Guidelines

### Project Structure
Create a well-organized project structure complian with Vue.js and Vuetify best practices. The root folder for the code is code/fe in this repository. Create src folder there.

### Code Quality Standards
- **TypeScript**: Use strict mode, define interfaces for all data structures
- **Vue Components**: Use Composition API with `<script setup>`
- **State Management**: Use Pinia stores for complex state, props/events for simple parent-child communication
- **API Layer**: Create dedicated service classes for API calls with proper error handling
- **Error Handling**: Implement global error handling and user-friendly error messages
- **Validation**: Use form validation with clear error states
- **Performance**: Implement lazy loading for routes and components where appropriate

### Component Guidelines
- Create reusable, single-responsibility components
- Use Vuetify components as base, customize with CSS variables
- Implement proper loading and error states
- Add TypeScript props validation
- Include JSDoc comments for complex components

### State Management
- **Pinia Stores**: Create separate stores for different domains (auth, tasks, users, etc.)
- **API Integration**: Handle loading states, error states, and success states in stores
- **Data Normalization**: Structure data efficiently for easy updates and queries
- **Persistence**: Consider which state should persist across sessions

### Testing Requirements
- Unit tests for utility functions and composables
- Component tests for critical UI components
- Integration tests for key user flows
- Mock API responses for consistent testing

## Specific Implementation Requests

### Authentication Flow

Implement complete authentication with:
- Login/register forms with validation
- JWT token management (storage, refresh, expiry)
- Route guards for protected pages
- Automatic logout on token expiry
- Remember me functionality


### Data Management

Create efficient data handling:
- Axios interceptors for authentication and error handling
- Loading states for all async operations
- Optimistic updates where appropriate
- Data caching strategies
- Offline handling considerations


### User Experience
`
Ensure excellent UX:
- Smooth page transitions
- Loading skeletons for better perceived performance
- Toast notifications for user actions
- Confirmation dialogs for destructive actions
- Keyboard navigation support
- Accessible design patterns


## Deliverables

Please provide:

1. **Complete project setup** with all necessary dependencies and configuration files
2. **Folder structure** with all required directories and initial files
3. **Core application architecture** including router, stores, and main App component
4. **Authentication system** with login/logout functionality
5. **Main dashboard/home page** with basic layout and navigation
6. **API service layer** with error handling and interceptors
7. **Sample components** demonstrating best practices
8. **Basic styling setup** with Vuetify theme configuration
9. **Type definitions** for main data structures
10. **Development scripts** and documentation for running the project

## Code Style Preferences
- Use `<script setup>` syntax for all components
- Prefer composition over mixins
- Use explicit return types for functions
- Implement proper error boundaries
- Use semantic HTML and ARIA attributes for accessibility
- Follow Vue.js style guide conventions

## Additional Considerations
- **Performance**: Code splitting and lazy loading strategies
- **SEO**: Meta tags and proper page titles
- **PWA**: Consider service worker for offline functionality
- **Analytics**: Integration points for tracking user interactions
- **Internationalization**: Structure for potential multi-language support

---

**Please start by creating the basic project structure and core setup, then implement features incrementally. Ask for clarification on any requirements that need more detail.**