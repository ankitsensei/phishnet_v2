import express from 'express';
import cors from 'cors';
import apiRouter from './routes/api';

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Mount API router
app.use('/api', apiRouter);

// Root healthcheck
app.get('/', (_req, res) => {
  res.json({
    platform: 'PhishNet V2 Sentinel Engine',
    status: 'ONLINE',
    version: '2.0.0',
    docs: '/api/health'
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 PhishNet V2 Full-Stack Backend Server`);
  console.log(`📡 Listening on: http://localhost:${PORT}`);
  console.log(`🛡️  Live Scanner, APK Lab, CT Streamer, Takedowns Active`);
  console.log(`=======================================================`);
});
