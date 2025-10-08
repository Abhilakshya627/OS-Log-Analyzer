# React Frontend

## Development Setup

### Prerequisites
- Node.js 16+ installed
- npm or yarn package manager

### Installation
```bash
cd frontend
npm install
```

### Development Server
```bash
npm run dev
```
This will start the React development server on http://localhost:3000

### Production Build
```bash
npm run build
```
This creates an optimized production build in the `dist` folder.

### Environment Variables
Create a `.env` file in the frontend directory for environment-specific settings:
```
VITE_API_BASE_URL=http://localhost:5000/api
```

## Features
- Real-time log streaming
- Interactive dashboard
- Threat detection alerts
- ML anomaly visualization
- System statistics with charts
- Export functionality
- Responsive design

## Architecture
- React 18 with hooks
- Vite for fast development and building
- Axios for API communication
- Chart.js for data visualization
- CSS modules for styling