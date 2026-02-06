require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validUrl = require('valid-url');
const shortid = require('shortid');
const path = require('path');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const cron = require('node-cron');

const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', true);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => {
    return req.headers['x-real-ip'] || 
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.ip;
  }
});
app.use('/api/', limiter);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/urlshortener';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB')).catch(err => console.error('❌ MongoDB connection error:', err));

const analyticsSchema = new mongoose.Schema({
  shortId: { type: String, required: true, index: true },
  ip: String,
  userAgent: String,
  country: String,
  countryCode: String,
  region: String,
  regionCode: String,
  city: String,
  isp: String,
  latitude: Number,
  longitude: Number,
  browser: String,
  os: String,
  device: String,
  referrer: String,
  timestamp: { type: Date, default: Date.now }
});

const urlSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true, index: true },
  originalUrl: { type: String, required: true },
  title: String,
  description: String,
  favicon: String,
  clicks: { type: Number, default: 0 },
  maxClicks: { type: Number, default: null },
  password: { type: String, default: null },
  requiresPassword: { type: Boolean, default: false },
  deleteAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(+new Date() + 30 * 24 * 60 * 60 * 1000) },
  createdBy: { type: String, default: 'web' }
});

urlSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
urlSchema.index({ deleteAt: 1 }, { expireAfterSeconds: 0 });
urlSchema.index({ createdAt: -1 });

const Url = mongoose.model('Url', urlSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);

const countryNames = {
  'ID': 'Indonesia',
  'US': 'United States',
  'GB': 'United Kingdom',
  'SG': 'Singapore',
  'MY': 'Malaysia',
  'JP': 'Japan',
  'KR': 'South Korea',
  'AU': 'Australia',
  'DE': 'Germany',
  'FR': 'France',
  'CA': 'Canada',
  'BR': 'Brazil',
  'IN': 'India',
  'CN': 'China',
  'RU': 'Russia',
  'SA': 'Saudi Arabia',
  'AE': 'United Arab Emirates',
  'TH': 'Thailand',
  'VN': 'Vietnam',
  'PH': 'Philippines',
  'MM': 'Myanmar',
  'KH': 'Cambodia',
  'LA': 'Laos'
};

const getClientIP = (req) => {
  return req.headers['x-real-ip'] || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['cf-connecting-ip'] ||
         req.ip ||
         '0.0.0.0';
};

const getGeoFromHeaders = (req) => {
  const countryCode = req.headers['x-vercel-ip-country'] || req.headers['cf-ipcountry'] || null;
  const country = countryCode ? (countryNames[countryCode] || countryCode) : 'Unknown';
  
  return {
    country,
    countryCode,
    region: req.headers['x-vercel-ip-country-region'] || req.headers['cf-region'] || null,
    regionCode: req.headers['x-vercel-ip-country-region'] || null,
    city: req.headers['x-vercel-ip-city'] || req.headers['cf-city'] || null,
    isp: req.headers['x-vercel-ip-as-number'] ? `AS${req.headers['x-vercel-ip-as-number']}` : null,
    latitude: req.headers['x-vercel-ip-latitude'] ? parseFloat(req.headers['x-vercel-ip-latitude']) : null,
    longitude: req.headers['x-vercel-ip-longitude'] ? parseFloat(req.headers['x-vercel-ip-longitude']) : null
  };
};

const parseUserAgent = (ua) => {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };
  
  let browser = 'Other';
  let os = 'Other';
  let device = 'Desktop';
  
  if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('Opera')) browser = 'Opera';
  else if (ua.includes('Brave')) browser = 'Brave';
  
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iOS') || ua.includes('iPhone')) os = 'iOS';
  else if (ua.includes('iPad')) os = 'iPadOS';
  
  if (ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone')) device = 'Mobile';
  else if (ua.includes('Tablet') || ua.includes('iPad')) device = 'Tablet';
  else if (ua.includes('TV')) device = 'TV';
  else if (ua.includes('Bot') || ua.includes('bot')) device = 'Bot';
  
  return { browser, os, device };
};

if (process.env.NODE_ENV === 'production') {
  cron.schedule('0 * * * *', async () => {
    try {
      const expired = await Url.deleteMany({ 
        $or: [
          { maxClicks: { $ne: null, $lte: { $expr: '$clicks' } } },
          { deleteAt: { $ne: null, $lte: new Date() } }
        ]
      });
      if (expired.deletedCount > 0) {
        console.log(`🔄 Cron: Deleted ${expired.deletedCount} expired URLs`);
      }
    } catch (error) {
      console.error('❌ Cron job error:', error);
    }
  });
}

// Middleware untuk menyimpan history di local storage
app.use((req, res, next) => {
  res.locals.saveHistory = true;
  next();
});

app.get('/', (req, res) => {
  res.render('index', { 
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
    isVercel: process.env.VERCEL === '1'
  });
});

app.get('/debug/geo', (req, res) => {
  const geo = getGeoFromHeaders(req);
  const ua = parseUserAgent(req.headers['user-agent']);
  
  res.json({
    headers: {
      'x-vercel-ip-country': req.headers['x-vercel-ip-country'],
      'x-vercel-ip-country-region': req.headers['x-vercel-ip-country-region'],
      'x-vercel-ip-city': req.headers['x-vercel-ip-city'],
      'x-vercel-ip-as-number': req.headers['x-vercel-ip-as-number'],
      'x-vercel-ip-latitude': req.headers['x-vercel-ip-latitude'],
      'x-vercel-ip-longitude': req.headers['x-vercel-ip-longitude'],
      'cf-ipcountry': req.headers['cf-ipcountry'],
      'cf-region': req.headers['cf-region'],
      'cf-city': req.headers['cf-city']
    },
    geo,
    userAgent: ua,
    ip: getClientIP(req),
    isVercel: process.env.VERCEL === '1'
  });
});

app.get('/dashboard', async (req, res) => {
  try {
    const urls = await Url.find().sort({ createdAt: -1 }).limit(50);
    const totalUrls = await Url.countDocuments();
    const totalClicks = await Url.aggregate([{ $group: { _id: null, total: { $sum: "$clicks" } } }]);
    const todayClicks = await Analytics.countDocuments({
      timestamp: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    
    res.render('dashboard', {
      urls,
      totalUrls,
      totalClicks: totalClicks[0]?.total || 0,
      todayClicks,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).render('error', { message: 'Error loading dashboard' });
  }
});

app.post('/api/shorten', async (req, res) => {
  try {
    const { originalUrl, customId, expiresInDays, password, maxClicks, deleteAt, title, description } = req.body;
    
    if (!validUrl.isWebUri(originalUrl)) {
      return res.status(400).json({ success: false, error: 'Invalid URL' });
    }
    
    const existingUrl = await Url.findOne({ originalUrl });
    if (existingUrl && !customId) {
      return res.json({
        success: true,
        shortUrl: `${req.protocol}://${req.get('host')}/${existingUrl.shortId}`,
        existing: true,
        shortId: existingUrl.shortId
      });
    }
    
    let shortId;
    if (customId) {
      if (!/^[a-zA-Z0-9_-]{3,20}$/.test(customId)) {
        return res.status(400).json({ success: false, error: 'Invalid custom ID (3-20 chars, alphanumeric, dash, underscore)' });
      }
      const existingCustom = await Url.findOne({ shortId: customId });
      if (existingCustom) return res.status(400).json({ success: false, error: 'Custom ID already in use' });
      shortId = customId;
    } else {
      do {
        shortId = shortid.generate().toLowerCase();
      } while (await Url.exists({ shortId }));
    }
    
    let expiresAt = new Date();
    const days = parseInt(expiresInDays) || 30;
    expiresAt.setDate(expiresAt.getDate() + days);
    
    let hashedPassword = null;
    let requiresPassword = false;
    if (password && password.trim() !== '') {
      hashedPassword = await bcrypt.hash(password, 10);
      requiresPassword = true;
    }
    
    const url = new Url({
      shortId,
      originalUrl,
      title: title || null,
      description: description || null,
      expiresAt,
      password: hashedPassword,
      requiresPassword,
      maxClicks: maxClicks ? parseInt(maxClicks) : null,
      deleteAt: deleteAt ? new Date(deleteAt) : null,
      createdBy: 'web'
    });
    
    await url.save();
    
    // Simpan ke history local storage
    const historyItem = {
      shortUrl: `${req.protocol}://${req.get('host')}/${shortId}`,
      originalUrl,
      shortId,
      createdAt: new Date().toISOString(),
      requiresPassword,
      maxClicks: url.maxClicks
    };
    
    res.json({
      success: true,
      shortUrl: `${req.protocol}://${req.get('host')}/${shortId}`,
      originalUrl,
      shortId,
      expiresAt,
      requiresPassword,
      maxClicks: url.maxClicks,
      deleteAt: url.deleteAt,
      qrCode: `${req.protocol}://${req.get('host')}/${shortId}/qr`,
      historyItem: historyItem
    });
    
  } catch (error) {
    console.error('Shorten error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/:shortId/qr', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    const shortUrl = `${req.protocol}://${req.get('host')}/${shortId}`;
    const qrCode = await QRCode.toDataURL(shortUrl, {
      errorCorrectionLevel: 'H',
      margin: 2,
      width: 400
    });
    
    res.render('qr', {
      shortUrl,
      qrCode,
      shortId,
      originalUrl: url.originalUrl,
      clicks: url.clicks,
      requiresPassword: url.requiresPassword,
      maxClicks: url.maxClicks,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    res.status(500).render('error', { message: 'Error generating QR code' });
  }
});

app.get('/:shortId/stats', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    const analytics = await Analytics.find({ shortId }).sort({ timestamp: -1 }).limit(100);
    
    const dailyClicks = await Analytics.aggregate([
      { $match: { shortId } },
      { $group: { 
        _id: { 
          year: { $year: "$timestamp" },
          month: { $month: "$timestamp" },
          day: { $dayOfMonth: "$timestamp" }
        }, 
        count: { $sum: 1 },
        date: { $first: "$timestamp" }
      } },
      { $sort: { "_id.year": 1, "_id.month": 1, "_id.day": 1 } },
      { $limit: 30 }
    ]);
    
    const hourlyClicks = await Analytics.aggregate([
      { $match: { 
        shortId, 
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
      } },
      { $group: { 
        _id: { $hour: "$timestamp" }, 
        count: { $sum: 1 } 
      } },
      { $sort: { _id: 1 } }
    ]);
    
    const countries = await Analytics.aggregate([
      { $match: { shortId, country: { $ne: null } } },
      { $group: { _id: "$country", count: { $sum: 1 }, code: { $first: "$countryCode" } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    const devices = await Analytics.aggregate([
      { $match: { shortId, device: { $ne: null } } },
      { $group: { _id: "$device", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const browsers = await Analytics.aggregate([
      { $match: { shortId, browser: { $ne: null } } },
      { $group: { _id: "$browser", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const osData = await Analytics.aggregate([
      { $match: { shortId, os: { $ne: null } } },
      { $group: { _id: "$os", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const referrers = await Analytics.aggregate([
      { $match: { 
        shortId, 
        referrer: { $ne: null, $ne: "Direct", $exists: true } 
      } },
      { $group: { _id: "$referrer", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    const cities = await Analytics.aggregate([
      { $match: { shortId, city: { $ne: null } } },
      { $group: { _id: "$city", count: { $sum: 1 }, country: { $first: "$country" } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    res.render('stats', {
      url,
      analytics,
      dailyClicks: dailyClicks.map(d => ({
        date: new Date(d.date).toISOString().split('T')[0],
        count: d.count
      })),
      hourlyClicks: hourlyClicks.map(h => ({ hour: h._id, count: h.count })),
      countries,
      devices,
      browsers,
      osData,
      referrers,
      cities,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).render('error', { message: 'Error loading statistics' });
  }
});

app.get('/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    
    if (!url) return res.status(404).render('404', { shortId });
    
    // Cek max clicks TERLEBIH DAHULU sebelum password
    if (url.maxClicks && url.clicks >= url.maxClicks) {
      await Url.deleteOne({ shortId });
      await Analytics.deleteMany({ shortId });
      return res.status(410).render('error', { 
        message: 'This link has expired (max clicks reached)',
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    // Cek password
    if (url.requiresPassword && !req.query.password) {
      return res.render('password', { 
        shortId,
        maxClicks: url.maxClicks,
        currentClicks: url.clicks,
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    if (url.requiresPassword && req.query.password) {
      const validPassword = await bcrypt.compare(req.query.password, url.password);
      if (!validPassword) {
        return res.render('password', { 
          shortId, 
          error: 'Invalid password',
          maxClicks: url.maxClicks,
          currentClicks: url.clicks,
          APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
        });
      }
    }
    
    const clientIP = getClientIP(req);
    const geo = getGeoFromHeaders(req);
    const userAgent = parseUserAgent(req.headers['user-agent'] || '');
    
    const analytic = new Analytics({
      shortId,
      ip: clientIP,
      userAgent: req.headers['user-agent'] || 'Unknown',
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.region,
      regionCode: geo.regionCode,
      city: geo.city,
      isp: geo.isp,
      latitude: geo.latitude,
      longitude: geo.longitude,
      browser: userAgent.browser,
      os: userAgent.os,
      device: userAgent.device,
      referrer: req.get('referer') || 'Direct'
    });
    
    await analytic.save();
    
    await Url.findOneAndUpdate(
      { shortId },
      { $inc: { clicks: 1 } },
      { new: true }
    );
    
    // Jika sudah mencapai max clicks, hapus setelah redirect
    const updatedUrl = await Url.findOne({ shortId });
    if (updatedUrl.maxClicks && updatedUrl.clicks >= updatedUrl.maxClicks) {
      setTimeout(async () => {
        await Url.deleteOne({ shortId });
        await Analytics.deleteMany({ shortId });
      }, 1000);
    }
    
    res.redirect(302, url.originalUrl);
    
  } catch (error) {
    console.error('Redirect error:', error);
    res.status(500).render('error', { 
      message: 'Server error',
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
    });
  }
});

app.post('/:shortId/verify', async (req, res) => {
  try {
    const { shortId } = req.params;
    const { password } = req.body;
    
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    // Cek max clicks
    if (url.maxClicks && url.clicks >= url.maxClicks) {
      await Url.deleteOne({ shortId });
      await Analytics.deleteMany({ shortId });
      return res.status(410).render('error', { 
        message: 'This link has expired (max clicks reached)',
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    if (!url.requiresPassword) {
      return res.redirect(`/${shortId}`);
    }
    
    const validPassword = await bcrypt.compare(password, url.password);
    if (!validPassword) {
      return res.render('password', { 
        shortId, 
        error: 'Invalid password',
        maxClicks: url.maxClicks,
        currentClicks: url.clicks,
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    const encodedPassword = encodeURIComponent(password);
    res.redirect(`/${shortId}?password=${encodedPassword}`);
  } catch (error) {
    res.status(500).render('error', { message: 'Verification error' });
  }
});

app.get('/api/stats/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).json({ success: false, error: 'URL not found' });
    
    const analytics = await Analytics.find({ shortId }).sort({ timestamp: -1 }).limit(50);
    const totalClicks = url.clicks;
    
    const countryStats = await Analytics.aggregate([
      { $match: { shortId, country: { $ne: null } } },
      { $group: { _id: "$country", count: { $sum: 1 }, code: { $first: "$countryCode" } } },
      { $sort: { count: -1 } }
    ]);
    
    const deviceStats = await Analytics.aggregate([
      { $match: { shortId, device: { $ne: null } } },
      { $group: { _id: "$device", count: { $sum: 1 } } }
    ]);
    
    const recentClicks = await Analytics.find({ shortId })
      .sort({ timestamp: -1 })
      .limit(10)
      .select('timestamp country city device browser referrer -_id');
    
    res.json({
      success: true,
      data: {
        shortId: url.shortId,
        originalUrl: url.originalUrl,
        clicks: totalClicks,
        maxClicks: url.maxClicks,
        requiresPassword: url.requiresPassword,
        createdAt: url.createdAt,
        expiresAt: url.expiresAt,
        deleteAt: url.deleteAt,
        countries: countryStats,
        devices: deviceStats,
        recentClicks,
        totalAnalytics: analytics.length
      }
    });
  } catch (error) {
    console.error('API Stats error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/realtime/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).json({ success: false, error: 'URL not found' });
    
    // Get clicks from last 5 minutes
    const recentClicks = await Analytics.countDocuments({
      shortId,
      timestamp: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
    });
    
    res.json({
      success: true,
      data: {
        shortId: url.shortId,
        clicks: url.clicks,
        recentClicks,
        maxClicks: url.maxClicks,
        requiresPassword: url.requiresPassword,
        updatedAt: new Date()
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/delete/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const result = await Url.deleteOne({ shortId });
    if (result.deletedCount > 0) {
      await Analytics.deleteMany({ shortId });
      res.json({ success: true, message: 'URL deleted successfully' });
    } else {
      res.status(404).json({ success: false, error: 'URL not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/history', (req, res) => {
  res.json({
    success: true,
    message: 'History should be managed in localStorage'
  });
});

app.get('/api/health', (req, res) => {
  const geo = getGeoFromHeaders(req);
  
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    vercel: process.env.VERCEL === '1',
    geo: {
      ip: getClientIP(req),
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.region,
      city: geo.city,
      isp: geo.isp
    },
    headers: {
      'x-real-ip': req.headers['x-real-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-vercel-ip-country': req.headers['x-vercel-ip-country'],
      'x-vercel-ip-city': req.headers['x-vercel-ip-city']
    }
  });
});

app.use((req, res) => {
  res.status(404).render('404', { 
    shortId: req.path.slice(1),
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
  });
});

app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  res.status(500).render('error', { 
    message: 'Something went wrong!',
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
  });
});

// Export untuk Vercel
if (process.env.NODE_ENV === 'production') {
  module.exports = app;
} else {
  app.listen(port, () => {
    console.log(`🚀 URL Shortener running on port ${port}`);
    console.log(`🌐 Local: http://localhost:${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}/dashboard`);
    console.log(`🔧 Debug: http://localhost:${port}/debug/geo`);
  });
}
/*
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validUrl = require('valid-url');
const shortid = require('shortid');
const path = require('path');
const QRCode = require('qrcode');
const bcrypt = require('bcrypt');
const cron = require('node-cron');

const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', true);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => {
    return req.headers['x-real-ip'] || 
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.ip;
  }
});
app.use('/api/', limiter);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/urlshortener';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB')).catch(err => console.error('❌ MongoDB connection error:', err));

const analyticsSchema = new mongoose.Schema({
  shortId: { type: String, required: true, index: true },
  ip: String,
  userAgent: String,
  country: String,
  countryCode: String,
  region: String,
  regionCode: String,
  city: String,
  isp: String,
  latitude: Number,
  longitude: Number,
  browser: String,
  os: String,
  device: String,
  referrer: String,
  timestamp: { type: Date, default: Date.now }
});

const urlSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true, index: true },
  originalUrl: { type: String, required: true },
  title: String,
  description: String,
  favicon: String,
  clicks: { type: Number, default: 0 },
  maxClicks: { type: Number, default: null },
  password: { type: String, default: null },
  requiresPassword: { type: Boolean, default: false },
  deleteAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(+new Date() + 30 * 24 * 60 * 60 * 1000) },
  createdBy: { type: String, default: 'web' }
});

urlSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
urlSchema.index({ deleteAt: 1 }, { expireAfterSeconds: 0 });
urlSchema.index({ createdAt: -1 });

const Url = mongoose.model('Url', urlSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);

const countryNames = {
  'ID': 'Indonesia',
  'US': 'United States',
  'GB': 'United Kingdom',
  'SG': 'Singapore',
  'MY': 'Malaysia',
  'JP': 'Japan',
  'KR': 'South Korea',
  'AU': 'Australia',
  'DE': 'Germany',
  'FR': 'France',
  'CA': 'Canada',
  'BR': 'Brazil',
  'IN': 'India',
  'CN': 'China',
  'RU': 'Russia',
  'SA': 'Saudi Arabia',
  'AE': 'United Arab Emirates',
  'TH': 'Thailand',
  'VN': 'Vietnam',
  'PH': 'Philippines',
  'MM': 'Myanmar',
  'KH': 'Cambodia',
  'LA': 'Laos'
};

const getClientIP = (req) => {
  return req.headers['x-real-ip'] || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['cf-connecting-ip'] ||
         req.ip ||
         '0.0.0.0';
};

const getGeoFromHeaders = (req) => {
  const countryCode = req.headers['x-vercel-ip-country'] || req.headers['cf-ipcountry'] || null;
  const country = countryCode ? (countryNames[countryCode] || countryCode) : 'Unknown';
  
  return {
    country,
    countryCode,
    region: req.headers['x-vercel-ip-country-region'] || req.headers['cf-region'] || null,
    regionCode: req.headers['x-vercel-ip-country-region'] || null,
    city: req.headers['x-vercel-ip-city'] || req.headers['cf-city'] || null,
    isp: req.headers['x-vercel-ip-as-number'] ? `AS${req.headers['x-vercel-ip-as-number']}` : null,
    latitude: req.headers['x-vercel-ip-latitude'] ? parseFloat(req.headers['x-vercel-ip-latitude']) : null,
    longitude: req.headers['x-vercel-ip-longitude'] ? parseFloat(req.headers['x-vercel-ip-longitude']) : null
  };
};

const parseUserAgent = (ua) => {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };
  
  let browser = 'Other';
  let os = 'Other';
  let device = 'Desktop';
  
  if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('Opera')) browser = 'Opera';
  else if (ua.includes('Brave')) browser = 'Brave';
  
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iOS') || ua.includes('iPhone')) os = 'iOS';
  else if (ua.includes('iPad')) os = 'iPadOS';
  
  if (ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone')) device = 'Mobile';
  else if (ua.includes('Tablet') || ua.includes('iPad')) device = 'Tablet';
  else if (ua.includes('TV')) device = 'TV';
  else if (ua.includes('Bot') || ua.includes('bot')) device = 'Bot';
  
  return { browser, os, device };
};

if (process.env.NODE_ENV === 'production') {
  cron.schedule('0 * * * *', async () => {
    try {
      const expired = await Url.deleteMany({ 
        $or: [
          { maxClicks: { $ne: null, $lte: { $expr: '$clicks' } } },
          { deleteAt: { $ne: null, $lte: new Date() } }
        ]
      });
      if (expired.deletedCount > 0) {
        console.log(`🔄 Cron: Deleted ${expired.deletedCount} expired URLs`);
      }
    } catch (error) {
      console.error('❌ Cron job error:', error);
    }
  });
}

app.get('/', (req, res) => {
  res.render('index', { 
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
    isVercel: process.env.VERCEL === '1'
  });
});

app.get('/debug/geo', (req, res) => {
  const geo = getGeoFromHeaders(req);
  const ua = parseUserAgent(req.headers['user-agent']);
  
  res.json({
    headers: {
      'x-vercel-ip-country': req.headers['x-vercel-ip-country'],
      'x-vercel-ip-country-region': req.headers['x-vercel-ip-country-region'],
      'x-vercel-ip-city': req.headers['x-vercel-ip-city'],
      'x-vercel-ip-as-number': req.headers['x-vercel-ip-as-number'],
      'x-vercel-ip-latitude': req.headers['x-vercel-ip-latitude'],
      'x-vercel-ip-longitude': req.headers['x-vercel-ip-longitude'],
      'cf-ipcountry': req.headers['cf-ipcountry'],
      'cf-region': req.headers['cf-region'],
      'cf-city': req.headers['cf-city']
    },
    geo,
    userAgent: ua,
    ip: getClientIP(req),
    isVercel: process.env.VERCEL === '1'
  });
});

app.get('/dashboard', async (req, res) => {
  try {
    const urls = await Url.find().sort({ createdAt: -1 }).limit(50);
    const totalUrls = await Url.countDocuments();
    const totalClicks = await Url.aggregate([{ $group: { _id: null, total: { $sum: "$clicks" } } }]);
    const todayClicks = await Analytics.countDocuments({
      timestamp: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    
    res.render('dashboard', {
      urls,
      totalUrls,
      totalClicks: totalClicks[0]?.total || 0,
      todayClicks,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).render('error', { message: 'Error loading dashboard' });
  }
});

app.post('/api/shorten', async (req, res) => {
  try {
    const { originalUrl, customId, expiresInDays, password, maxClicks, deleteAt, title, description } = req.body;
    
    if (!validUrl.isWebUri(originalUrl)) {
      return res.status(400).json({ success: false, error: 'Invalid URL' });
    }
    
    const existingUrl = await Url.findOne({ originalUrl });
    if (existingUrl && !customId) {
      return res.json({
        success: true,
        shortUrl: `${req.protocol}://${req.get('host')}/${existingUrl.shortId}`,
        existing: true,
        shortId: existingUrl.shortId
      });
    }
    
    let shortId;
    if (customId) {
      if (!/^[a-zA-Z0-9_-]{3,20}$/.test(customId)) {
        return res.status(400).json({ success: false, error: 'Invalid custom ID (3-20 chars, alphanumeric, dash, underscore)' });
      }
      const existingCustom = await Url.findOne({ shortId: customId });
      if (existingCustom) return res.status(400).json({ success: false, error: 'Custom ID already in use' });
      shortId = customId;
    } else {
      do {
        shortId = shortid.generate().toLowerCase();
      } while (await Url.exists({ shortId }));
    }
    
    let expiresAt = new Date();
    const days = parseInt(expiresInDays) || 30;
    expiresAt.setDate(expiresAt.getDate() + days);
    
    let hashedPassword = null;
    let requiresPassword = false;
    if (password && password.trim() !== '') {
      hashedPassword = await bcrypt.hash(password, 10);
      requiresPassword = true;
    }
    
    const url = new Url({
      shortId,
      originalUrl,
      title: title || null,
      description: description || null,
      expiresAt,
      password: hashedPassword,
      requiresPassword,
      maxClicks: maxClicks ? parseInt(maxClicks) : null,
      deleteAt: deleteAt ? new Date(deleteAt) : null,
      createdBy: req.headers['x-telegram-id'] ? 'telegram' : 'web'
    });
    
    await url.save();
    
    res.json({
      success: true,
      shortUrl: `${req.protocol}://${req.get('host')}/${shortId}`,
      originalUrl,
      shortId,
      expiresAt,
      requiresPassword,
      maxClicks: url.maxClicks,
      deleteAt: url.deleteAt,
      qrCode: `${req.protocol}://${req.get('host')}/${shortId}/qr`
    });
    
  } catch (error) {
    console.error('Shorten error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/:shortId/qr', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    const shortUrl = `${req.protocol}://${req.get('host')}/${shortId}`;
    const qrCode = await QRCode.toDataURL(shortUrl, {
      errorCorrectionLevel: 'H',
      margin: 2,
      width: 400
    });
    
    res.render('qr', {
      shortUrl,
      qrCode,
      shortId,
      originalUrl: url.originalUrl,
      clicks: url.clicks,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    res.status(500).render('error', { message: 'Error generating QR code' });
  }
});

app.get('/:shortId/stats', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    const analytics = await Analytics.find({ shortId }).sort({ timestamp: -1 }).limit(100);
    
    const dailyClicks = await Analytics.aggregate([
      { $match: { shortId } },
      { $group: { 
        _id: { 
          year: { $year: "$timestamp" },
          month: { $month: "$timestamp" },
          day: { $dayOfMonth: "$timestamp" }
        }, 
        count: { $sum: 1 },
        date: { $first: "$timestamp" }
      } },
      { $sort: { "_id.year": 1, "_id.month": 1, "_id.day": 1 } },
      { $limit: 30 }
    ]);
    
    const hourlyClicks = await Analytics.aggregate([
      { $match: { 
        shortId, 
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
      } },
      { $group: { 
        _id: { $hour: "$timestamp" }, 
        count: { $sum: 1 } 
      } },
      { $sort: { _id: 1 } }
    ]);
    
    const countries = await Analytics.aggregate([
      { $match: { shortId, country: { $ne: null } } },
      { $group: { _id: "$country", count: { $sum: 1 }, code: { $first: "$countryCode" } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    const devices = await Analytics.aggregate([
      { $match: { shortId, device: { $ne: null } } },
      { $group: { _id: "$device", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const browsers = await Analytics.aggregate([
      { $match: { shortId, browser: { $ne: null } } },
      { $group: { _id: "$browser", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const osData = await Analytics.aggregate([
      { $match: { shortId, os: { $ne: null } } },
      { $group: { _id: "$os", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const referrers = await Analytics.aggregate([
      { $match: { 
        shortId, 
        referrer: { $ne: null, $ne: "Direct", $exists: true } 
      } },
      { $group: { _id: "$referrer", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    const cities = await Analytics.aggregate([
      { $match: { shortId, city: { $ne: null } } },
      { $group: { _id: "$city", count: { $sum: 1 }, country: { $first: "$country" } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    res.render('stats', {
      url,
      analytics,
      dailyClicks: dailyClicks.map(d => ({
        date: new Date(d.date).toISOString().split('T')[0],
        count: d.count
      })),
      hourlyClicks: hourlyClicks.map(h => ({ hour: h._id, count: h.count })),
      countries,
      devices,
      browsers,
      osData,
      referrers,
      cities,
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`,
      isVercel: process.env.VERCEL === '1'
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).render('error', { message: 'Error loading statistics' });
  }
});

app.get('/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    
    if (!url) return res.status(404).render('404', { shortId });
    
    if (url.maxClicks && url.clicks >= url.maxClicks) {
      await Url.deleteOne({ shortId });
      await Analytics.deleteMany({ shortId });
      return res.status(410).render('error', { 
        message: 'This link has expired (max clicks reached)',
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    if (url.requiresPassword && !req.query.password) {
      return res.render('password', { 
        shortId,
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    if (url.requiresPassword && req.query.password) {
      const validPassword = await bcrypt.compare(req.query.password, url.password);
      if (!validPassword) {
        return res.render('password', { 
          shortId, 
          error: 'Invalid password',
          APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
        });
      }
    }
    
    const clientIP = getClientIP(req);
    const geo = getGeoFromHeaders(req);
    const userAgent = parseUserAgent(req.headers['user-agent'] || '');
    
    const analytic = new Analytics({
      shortId,
      ip: clientIP,
      userAgent: req.headers['user-agent'] || 'Unknown',
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.region,
      regionCode: geo.regionCode,
      city: geo.city,
      isp: geo.isp,
      latitude: geo.latitude,
      longitude: geo.longitude,
      browser: userAgent.browser,
      os: userAgent.os,
      device: userAgent.device,
      referrer: req.get('referer') || 'Direct'
    });
    
    await analytic.save();
    
    await Url.findOneAndUpdate(
      { shortId },
      { $inc: { clicks: 1 } },
      { new: true }
    );
    
    res.redirect(302, url.originalUrl);
    
  } catch (error) {
    console.error('Redirect error:', error);
    res.status(500).render('error', { 
      message: 'Server error',
      APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
    });
  }
});

app.post('/:shortId/verify', async (req, res) => {
  try {
    const { shortId } = req.params;
    const { password } = req.body;
    
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).render('404', { shortId });
    
    if (!url.requiresPassword) {
      return res.redirect(`/${shortId}`);
    }
    
    const validPassword = await bcrypt.compare(password, url.password);
    if (!validPassword) {
      return res.render('password', { 
        shortId, 
        error: 'Invalid password',
        APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
      });
    }
    
    const encodedPassword = encodeURIComponent(password);
    res.redirect(`/${shortId}?password=${encodedPassword}`);
  } catch (error) {
    res.status(500).render('error', { message: 'Verification error' });
  }
});

app.get('/api/stats/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const url = await Url.findOne({ shortId });
    if (!url) return res.status(404).json({ success: false, error: 'URL not found' });
    
    const analytics = await Analytics.find({ shortId }).sort({ timestamp: -1 }).limit(50);
    const totalClicks = url.clicks;
    
    const countryStats = await Analytics.aggregate([
      { $match: { shortId, country: { $ne: null } } },
      { $group: { _id: "$country", count: { $sum: 1 }, code: { $first: "$countryCode" } } },
      { $sort: { count: -1 } }
    ]);
    
    const deviceStats = await Analytics.aggregate([
      { $match: { shortId, device: { $ne: null } } },
      { $group: { _id: "$device", count: { $sum: 1 } } }
    ]);
    
    const recentClicks = await Analytics.find({ shortId })
      .sort({ timestamp: -1 })
      .limit(10)
      .select('timestamp country city device browser referrer -_id');
    
    res.json({
      success: true,
      data: {
        shortId: url.shortId,
        originalUrl: url.originalUrl,
        clicks: totalClicks,
        maxClicks: url.maxClicks,
        requiresPassword: url.requiresPassword,
        createdAt: url.createdAt,
        expiresAt: url.expiresAt,
        deleteAt: url.deleteAt,
        countries: countryStats,
        devices: deviceStats,
        recentClicks,
        totalAnalytics: analytics.length
      }
    });
  } catch (error) {
    console.error('API Stats error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.delete('/api/delete/:shortId', async (req, res) => {
  try {
    const { shortId } = req.params;
    const result = await Url.deleteOne({ shortId });
    if (result.deletedCount > 0) {
      await Analytics.deleteMany({ shortId });
      res.json({ success: true, message: 'URL deleted successfully' });
    } else {
      res.status(404).json({ success: false, error: 'URL not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/health', (req, res) => {
  const geo = getGeoFromHeaders(req);
  
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    vercel: process.env.VERCEL === '1',
    geo: {
      ip: getClientIP(req),
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.region,
      city: geo.city,
      isp: geo.isp
    },
    headers: {
      'x-real-ip': req.headers['x-real-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-vercel-ip-country': req.headers['x-vercel-ip-country'],
      'x-vercel-ip-city': req.headers['x-vercel-ip-city']
    }
  });
});

app.get('/api/trending', async (req, res) => {
  try {
    const trending = await Url.find()
      .sort({ clicks: -1, createdAt: -1 })
      .limit(20)
      .select('shortId originalUrl clicks createdAt -_id');
    
    const totalClicks = await Url.aggregate([
      { $group: { _id: null, total: { $sum: "$clicks" } } }
    ]);
    
    res.json({
      success: true,
      data: {
        trending,
        totalClicks: totalClicks[0]?.total || 0,
        totalUrls: await Url.countDocuments()
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.use((req, res) => {
  res.status(404).render('404', { 
    shortId: req.path.slice(1),
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
  });
});

app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  res.status(500).render('error', { 
    message: 'Something went wrong!',
    APP_DOMAIN: process.env.APP_DOMAIN || `${req.protocol}://${req.get('host')}`
  });
});

// Export untuk Vercel
if (process.env.NODE_ENV === 'production') {
  module.exports = app;
} else {
  app.listen(port, () => {
    console.log(`🚀 URL Shortener running on port ${port}`);
    console.log(`🌐 Local: http://localhost:${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}/dashboard`);
    console.log(`🔧 Debug: http://localhost:${port}/debug/geo`);
  });
}

*/
