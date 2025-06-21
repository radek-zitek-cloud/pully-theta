# Vue.js 3 + TypeScript Frontend Application

A modern, production-ready Vue.js 3 frontend application with TypeScript, Vuetify 3, and comprehensive authentication integration with a Go-based backend service.

## 🚀 Features

### Core Technologies
- **Vue 3** with Composition API
- **TypeScript** for type safety
- **Vite** for fast development and building
- **Vuetify 3** for Material Design UI components
- **Pinia** for state management
- **Vue Router 4** for navigation
- **Axios** for HTTP requests

### Authentication & Security
- JWT-based authentication with automatic token refresh
- Protected routes with navigation guards
- Role-based access control
- Session management and logout functionality
- Remember me functionality
- Comprehensive error handling

### UI/UX Features
- **Responsive Design** - Mobile-first approach
- **Dark/Light Theme** - User-preferred theme switching
- **Sidebar Navigation** - Collapsible sidebar with menu items
- **Global Notifications** - Toast notifications system
- **Confirmation Dialogs** - User action confirmations
- **Loading States** - Page and component loading indicators
- **Error Pages** - 404 and 403 error handling

### Developer Experience
- **ESLint + Prettier** for code formatting
- **TypeScript** strict mode configuration
- **Path aliases** for clean imports
- **Hot module replacement** during development
- **Production optimizations** with Vite

## 📁 Project Structure

```
code/fe/
├── public/                     # Static assets
├── src/
│   ├── components/            # Reusable Vue components
│   │   ├── common/           # Common UI components
│   │   └── layout/           # Layout components
│   ├── layouts/              # Page layouts
│   ├── plugins/              # Vue plugins configuration
│   ├── router/               # Vue Router configuration
│   ├── services/             # API service layer
│   ├── stores/               # Pinia stores
│   ├── styles/               # Global styles and CSS
│   ├── types/                # TypeScript type definitions
│   ├── views/                # Page components
│   │   └── auth/             # Authentication pages
│   ├── App.vue               # Root component
│   └── main.ts               # Application entry point
├── .env                      # Environment variables (production)
├── .env.development          # Environment variables (development)
├── .eslintrc.cjs            # ESLint configuration
├── .gitignore               # Git ignore rules
├── .prettierrc.json         # Prettier configuration
├── package.json             # Dependencies and scripts
├── tsconfig.json            # TypeScript configuration
└── vite.config.ts           # Vite configuration
```

## 🛠️ Installation & Setup

### Prerequisites
- Node.js (v18+ recommended)
- npm or yarn package manager

### Installation

1. **Clone the repository** (if not already done)
```bash
git clone <repository-url>
cd code/fe
```

2. **Install dependencies**
```bash
npm install
# or
yarn install
```

3. **Environment Configuration**
```bash
# Copy environment files and update values
cp .env.example .env
cp .env.development.example .env.development
```

4. **Update environment variables**
Edit `.env` and `.env.development` files with your configuration:
```env
VITE_APP_TITLE=Your App Name
VITE_API_BASE_URL=http://localhost:8080/api/v1
VITE_API_TIMEOUT=30000
VITE_ENABLE_LOGGING=true
```

## 🚦 Available Scripts

### Development
```bash
# Start development server with hot reload
npm run dev
# or
yarn dev
```
Runs the app in development mode at `http://localhost:5173`

### Building
```bash
# Build for production
npm run build
# or
yarn build
```
Creates optimized production build in the `dist/` directory

### Preview
```bash
# Preview production build locally
npm run preview
# or
yarn preview
```

### Code Quality
```bash
# Run ESLint
npm run lint
# or
yarn lint

# Fix ESLint issues automatically
npm run lint:fix
# or
yarn lint:fix

# Format code with Prettier
npm run format
# or
yarn format
```

### Type Checking
```bash
# Run TypeScript type checking
npm run type-check
# or
yarn type-check
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_APP_TITLE` | Application title | `Vue App` |
| `VITE_API_BASE_URL` | Backend API base URL | `http://localhost:8080/api/v1` |
| `VITE_API_TIMEOUT` | HTTP request timeout (ms) | `30000` |
| `VITE_ENABLE_LOGGING` | Enable console logging | `true` |

### API Integration

The application is configured to work with a Go-based authentication service. The API endpoints include:

- `POST /auth/login` - User authentication
- `POST /auth/register` - User registration
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - User logout
- `GET /auth/profile` - Get user profile
- `PUT /auth/profile` - Update user profile

### Theming

The application supports light and dark themes with Vuetify 3. Theme preferences are:
- Automatically saved to localStorage
- System theme detection
- Manual theme switching via UI

## 📱 Components Overview

### Layout Components
- **AppHeader** - Top navigation bar with user menu
- **AppSidebar** - Collapsible navigation sidebar
- **AppFooter** - Application footer
- **AuthLayout** - Centered layout for authentication pages

### Common Components
- **NotificationSystem** - Global toast notifications
- **ConfirmationDialog** - Modal confirmation dialogs

### Views
- **DashboardView** - Main dashboard with statistics
- **LoginView** - User authentication form
- **RegisterView** - User registration form
- **ProfileView** - User profile display
- **EditProfileView** - Profile editing interface
- **SettingsView** - Application settings
- **NotFoundView** - 404 error page
- **UnauthorizedView** - 403 error page

## 🔐 Authentication Flow

1. **Login Process**
   - User submits credentials
   - JWT tokens received and stored securely
   - User redirected to dashboard or intended page

2. **Token Management**
   - Access tokens stored in memory
   - Refresh tokens stored in httpOnly cookies (when available)
   - Automatic token refresh on API calls
   - Token cleanup on logout

3. **Route Protection**
   - Navigation guards check authentication status
   - Automatic redirects to login for protected routes
   - Proper handling of expired sessions

## 🎨 Styling & Theming

### CSS Architecture
- **Global styles** in `src/styles/main.css`
- **Component-scoped styles** using Vue SFC style blocks
- **CSS custom properties** for theming
- **Responsive design** with Vuetify breakpoints

### Vuetify Configuration
- Material Design 3 theme system
- Custom color palettes
- Typography scale
- Component defaults

## 🧪 Testing (Planned)

The project is set up for testing with:
- **Vitest** for unit testing
- **@vue/test-utils** for component testing
- **Testing Library** utilities
- **Mock Service Worker** for API mocking

## 🚀 Deployment

### Production Build
```bash
npm run build
```

### Deployment Options
- **Static hosting** (Netlify, Vercel, GitHub Pages)
- **CDN deployment** with build artifacts
- **Docker containerization** (Dockerfile included)
- **CI/CD integration** ready

### Docker Deployment
```dockerfile
# Example Dockerfile (create in project root)
FROM node:18-alpine as build-stage
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM nginx:stable-alpine as production-stage
COPY --from=build-stage /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## 🔍 Performance Optimizations

- **Lazy loading** of routes and components
- **Code splitting** with dynamic imports
- **Tree shaking** for unused code elimination
- **Asset optimization** with Vite
- **HTTP/2 Push** headers for critical resources
- **Service Worker** support (can be added)

## 📈 Monitoring & Analytics

Ready for integration with:
- **Error tracking** (Sentry, Bugsnag)
- **Analytics** (Google Analytics, Mixpanel)
- **Performance monitoring** (Web Vitals)
- **User behavior tracking**

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Follow code standards** (ESLint + Prettier)
4. **Commit changes** (`git commit -m 'Add amazing feature'`)
5. **Push to branch** (`git push origin feature/amazing-feature`)
6. **Open a Pull Request**

### Code Standards
- Use TypeScript strict mode
- Follow Vue 3 Composition API patterns
- Write comprehensive component documentation
- Add proper error handling
- Include loading states
- Ensure responsive design

## 📋 TODO / Roadmap

### Immediate
- [ ] Add unit tests with Vitest
- [ ] Implement password reset flow
- [ ] Add email verification
- [ ] Create user management interfaces

### Short Term
- [ ] PWA functionality
- [ ] Internationalization (i18n)
- [ ] Advanced form validation
- [ ] File upload components
- [ ] Data tables with sorting/filtering

### Long Term
- [ ] Real-time features with WebSockets
- [ ] Advanced analytics dashboard
- [ ] Multi-tenant support
- [ ] Plugin system architecture

## 🐛 Troubleshooting

### Common Issues

**Development server won't start**
- Check Node.js version (18+ required)
- Clear `node_modules` and reinstall
- Check port 5173 availability

**Build fails**
- Run `npm run type-check` for TypeScript errors
- Check ESLint errors with `npm run lint`
- Verify environment variables

**API calls failing**
- Check `VITE_API_BASE_URL` in environment files
- Verify backend service is running
- Check browser network tab for CORS issues

**Authentication not working**
- Clear browser localStorage/sessionStorage
- Check JWT token format and expiration
- Verify API endpoint responses

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check existing documentation
- Review console errors and network requests
- Contact the development team

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Built with ❤️ using Vue.js 3, TypeScript, and modern web technologies.**
