require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const port = process.env.PORT || 5500;

// Configuration
const SECRET_KEY = process.env.SECRET_KEY || 'your-very-secure-default-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  next();
});

// Database Connection
const connectWithRetry = () => {
  const db_username = process.env.MONGODB_USER_NAME;
  const db_password = process.env.MONGODB_PASS;
  const dbURI = `mongodb+srv://${db_username}:${db_password}@userdata.8kbakbb.mongodb.net/MarketAppUserData?retryWrites=true&w=majority&appName=MarketAppUserData`;

  mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 30000
  })
  .then(() => console.log('Successfully connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    console.log('Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  });
};

connectWithRetry();

// Multer Configuration for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'public/uploads/profile');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `user-${req.user?.id || 'temp'}-${Date.now()}${ext}`;
    cb(null, filename);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Mongoose Schemas and Models
const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email address']
  },
  mobile: { 
    type: String,
    trim: true,
    match: [/^[0-9]{10,15}$/, 'Please provide a valid mobile number']
  },
  profileImg: { 
    type: String,
    default: ''
  },
  fullname: { 
    type: String,
    trim: true,
    maxlength: [100, 'Full name cannot exceed 100 characters']
  },
  password: { 
    type: String,
    minlength: [6, 'Password must be at least 6 characters long']
  },
  authProvider: {
    type: String,
    enum: ['google', 'manual'],
    required: [true, 'Authentication provider is required']
  },
  addresses: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Address' 
  }],
  devices: [{
    deviceId: { type: String, required: true },
    deviceName: String,
    os: String,
    lastLogin: { type: Date, default: Date.now },
    tokenVersion: { type: Number, default: 0 },
    fcmToken: String,
    isActive: { type: Boolean, default: true }
  }],
  tokenVersion: { type: Number, default: 0 },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const addressSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  mobile: {
    type: String,
    required: true,
    trim: true,
    maxlength: 10
  },
  addressLine1: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  addressLine2: {
    type: String,
    trim: true,
    maxlength: 200
  },
  city: {
    type: String,
    required: true,
    trim: true
  },
  state: {
    type: String,
    required: true,
    trim: true
  },
  postalCode: {
    type: String,
    required: true,
    trim: true,
    maxlength: 20
  },
  country: {
    type: String,
    required: true,
    trim: true
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});


const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  description: String,
  image: String,
  category: String,
  stock: { type: Number, default: 0 }
});

const cartItemSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, default: 1, min: 1 },
  price: { type: Number, required: true }
});

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [cartItemSchema],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const orderItemSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true }
});

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [orderItemSchema],
  shippingAddress: { type: mongoose.Schema.Types.ObjectId, ref: 'Address', required: true },
  paymentMethod: { type: String, required: true },
  paymentStatus: { type: String, default: 'pending' },
  status: { type: String, default: 'processing' },
  totalPrice: { type: Number, required: true },
  taxPrice: { type: Number, default: 0 },
  shippingPrice: { type: Number, default: 0 },
  deliveredAt: Date,
  createdAt: { type: Date, default: Date.now }
});

// Add timestamps update hooks
userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

addressSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

cartSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const User = mongoose.model('User', userSchema);
const Address = mongoose.model('Address', addressSchema);
const Product = mongoose.model('Product', productSchema);
const Cart = mongoose.model('Cart', cartSchema);
const Order = mongoose.model('Order', orderSchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Authentication token required' 
    });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await User.findById(decoded.id);
    
    if (!user || user.tokenVersion !== decoded.tokenVersion) {
      return res.status(403).json({
        success: false,
        message: 'Invalid token'
      });
    }

    const device = user.devices.find(d => d.deviceId === decoded.deviceId);
    if (!device || !device.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Device session expired'
      });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ 
      success: false,
      message: 'Invalid or expired token' 
    });
  }
};

// Helper function to handle errors
const handleError = (res, err, context = 'operation') => {
  console.error(`${context} error:`, err);
  
  let statusCode = 500;
  let message = 'Internal server error';
  
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = err.message;
  } else if (err.name === 'MongoServerError' && err.code === 11000) {
    statusCode = 409;
    message = 'Email already exists';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (err.message === 'Only image files are allowed!') {
    statusCode = 400;
    message = err.message;
  }
  
  res.status(statusCode).json({ 
    success: false,
    message 
  });
};

// API Routes

// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    success: true,
    message: 'API is healthy',
    timestamp: new Date(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Auth Routes

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { email, password, authProvider, deviceId, deviceInfo = {} } = req.body;

    if (authProvider === 'manual' && !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Password is required for manual registration' 
      });
    }

    const newUser = new User({
      ...req.body,
      devices: deviceId ? [{
        deviceId,
        deviceName: deviceInfo.deviceName || 'Unknown Device',
        os: deviceInfo.os || 'Unknown OS',
        lastLogin: new Date()
      }] : []
    });

    await newUser.save();

    const token = jwt.sign(
      { 
        id: newUser._id, 
        email: newUser.email,
        deviceId,
        tokenVersion: newUser.tokenVersion
      }, 
      SECRET_KEY
    );

    const userResponse = newUser.toObject();
    delete userResponse.password;

    res.status(201).json({ 
      success: true,
      message: 'User registered successfully',
      user: userResponse,
      token 
    });
  } catch (err) {
    handleError(res, err, 'Registration');
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password, authProvider, deviceId, deviceInfo } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    if (authProvider === 'manual' && !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Password is required for manual login' 
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    if (authProvider === 'manual' && user.password !== password) {
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    if (user.authProvider !== authProvider) {
      return res.status(400).json({ 
        success: false,
        message: `Please login using ${user.authProvider} authentication` 
      });
    }

    // Update or add device information
    let deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);
    if (deviceIndex >= 0) {
      user.devices[deviceIndex].lastLogin = new Date();
      user.devices[deviceIndex].isActive = true;
    } else {
      // Limit to 5 devices
      if (user.devices.length >= 5) {
        return res.status(403).json({
          success: false,
          message: 'Maximum device limit reached. Please logout from another device.'
        });
      }
      user.devices.push({
        deviceId,
        deviceName: deviceInfo.deviceName || 'Unknown Device',
        os: deviceInfo.os || 'Unknown OS',
        lastLogin: new Date()
      });
    }

    await user.save();

    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email,
        deviceId,
        tokenVersion: user.tokenVersion
      }, 
      SECRET_KEY
    );

    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(200).json({ 
      success: true,
      message: 'Login successful',
      user: userResponse,
      token 
    });
  } catch (err) {
    handleError(res, err, 'Login');
  }
});

// Logout
app.post('/logout', authenticateToken, async (req, res) => {
  try {
    const { deviceId } = req.user;
    await User.updateOne(
      { _id: req.user.id, 'devices.deviceId': deviceId },
      { $set: { 'devices.$.isActive': false } }
    );

    res.status(200).json({ 
      success: true,
      message: 'Logged out successfully'
    });
  } catch (err) {
    handleError(res, err, 'Logout');
  }
});

// Logout all devices
app.post('/logout-all', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, {
      $inc: { tokenVersion: 1 },
      $set: { 'devices.$[].isActive': false }
    });

    res.status(200).json({ 
      success: true,
      message: 'Logged out from all devices'
    });
  } catch (err) {
    handleError(res, err, 'Logout all');
  }
});

// Profile Routes

// Get User Profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password -__v')
      .populate('addresses');

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      user 
    });
  } catch (err) {
    handleError(res, err, 'Fetch profile');
  }
});

// Update User Profile
app.put('/profile', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    const userId = req.user.id;

    if (updates.email || updates.password || updates.authProvider) {
      return res.status(400).json({ 
        success: false,
        message: 'Email, password, or auth provider cannot be updated here' 
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: updates },
      { 
        new: true,
        runValidators: true,
        select: '-password -__v'
      }
    ).populate('addresses');

    if (!updatedUser) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (err) {
    handleError(res, err, 'Update profile');
  }
});

// Upload Profile Image
// app.post('/profile/image', authenticateToken, upload.single('image'), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({
//         success: false,
//         message: 'No image file provided'
//       });
//     }

//     const imagePath = `/public/uploads/profile/${req.file.filename}`;
//     const updatedUser = await User.findByIdAndUpdate(
//       req.user.id,
//       { profileImg: imagePath },
//       { new: true, select: '-password -__v' }
//     );

//     res.status(200).json({
//       success: true,
//       message: 'Profile image updated successfully',
//       profileImg: imagePath,
//       user: updatedUser
//     });
//   } catch (err) {
//     handleError(res, err, 'Profile image upload');
//   }
// });


//Updated Profile Image Upload

app.post('/profile/image', authenticateToken, async (req, res) => {
  try {
    const { image } = req.body;

    if (!image || !image.startsWith('data:image')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid image data'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { profileImg: image }, // Store base64 string directly
      { new: true, select: '-password -__v' }
    );

    res.status(200).json({
      success: true,
      message: 'Profile image updated successfully',
      profileImg: image,
      user: updatedUser
    });
  } catch (err) {
    handleError(res, err, 'Profile image upload');
  }
});


// Get active devices
app.get('/profile/devices', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('devices');

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.status(200).json({ 
      success: true,
      devices: user.devices 
    });
  } catch (err) {
    handleError(res, err, 'Get devices');
  }
});

// Address Routes

// Add Address
app.post('/addresses', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const addressData = { ...req.body, userId };

    // Create new address
    const newAddress = new Address(addressData);
    await newAddress.save();

    // Add address reference to user
    await User.findByIdAndUpdate(
      userId,
      { $push: { addresses: newAddress._id } }
    );

    // If this is the first address, set it as default
    if (!req.body.isDefault) {
      const user = await User.findById(userId).populate('addresses');
      if (user.addresses.length === 1) {
        newAddress.isDefault = true;
        await newAddress.save();
      }
    }

    res.status(201).json({ 
      success: true,
      message: 'Address added successfully',
      address: newAddress
    });
  } catch (err) {
    handleError(res, err, 'Add address');
  }
});

// Get All Addresses
app.get('/addresses', authenticateToken, async (req, res) => {
  try {
    const addresses = await Address.find({ userId: req.user.id })
      .sort({ isDefault: -1, updatedAt: -1 });

    res.status(200).json({ 
      success: true,
      addresses 
    });
  } catch (err) {
    handleError(res, err, 'Get addresses');
  }
});

// Update Address
app.put('/addresses/:addressId', authenticateToken, async (req, res) => {
  try {
    const { addressId } = req.params;
    const userId = req.user.id;
    const updates = req.body;

    // Verify address belongs to user
    const address = await Address.findOne({ _id: addressId, userId });
    if (!address) {
      return res.status(404).json({ 
        success: false,
        message: 'Address not found or unauthorized' 
      });
    }

    // If setting as default, unset other defaults
    if (updates.isDefault === true) {
      await Address.updateMany(
        { userId, _id: { $ne: addressId } },
        { $set: { isDefault: false } }
      );
    }

    const updatedAddress = await Address.findByIdAndUpdate(
      addressId,
      { $set: updates },
      { new: true, runValidators: true }
    );

    res.status(200).json({ 
      success: true,
      message: 'Address updated successfully',
      address: updatedAddress
    });
  } catch (err) {
    handleError(res, err, 'Update address');
  }
});

// Delete Address
app.delete('/addresses/:addressId', authenticateToken, async (req, res) => {
  try {
    const { addressId } = req.params;
    const userId = req.user.id;

    // Verify address belongs to user
    const address = await Address.findOne({ _id: addressId, userId });
    if (!address) {
      return res.status(404).json({ 
        success: false,
        message: 'Address not found or unauthorized' 
      });
    }

    // Remove address reference from user
    await User.findByIdAndUpdate(
      userId,
      { $pull: { addresses: addressId } }
    );

    // If deleting default address, set another as default
    if (address.isDefault) {
      const remainingAddress = await Address.findOne({ userId, _id: { $ne: addressId } });
      if (remainingAddress) {
        remainingAddress.isDefault = true;
        await remainingAddress.save();
      }
    }

    // Delete address
    await Address.findByIdAndDelete(addressId);

    res.status(200).json({ 
      success: true,
      message: 'Address deleted successfully'
    });
  } catch (err) {
    handleError(res, err, 'Delete address');
  }
});



// Add a new product (POST /api/products)
app.post('/product', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json({ message: 'Product created', product });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/bulk', async (req, res) => {
  try {
    const products = req.body;
    if (!Array.isArray(products)) {
      return res.status(400).json({ message: "Input must be an array of products." });
    }
    const result = await Product.insertMany(products, { ordered: false });
    res.status(201).json({ message: `${result.length} products inserted successfully.`, result });
  } catch (error) {
    res.status(500).json({ message: "Error inserting products", error: error.message });
  }
});

// Get all products (GET /api/products)
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cart Routes

// Get user's cart
app.get('/cart', authenticateToken, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id })
      .populate('items.product');

    if (!cart) {
      return res.status(200).json({
        success: true,
        cart: { items: [] }
      });
    }

    res.status(200).json({
      success: true,
      cart
    });
  } catch (err) {
    handleError(res, err, 'Get cart');
  }
});

// Add item to cart
app.post('/cart', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity } = req.body;

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    if (product.stock < quantity) {
      return res.status(400).json({
        success: false,
        message: 'Not enough stock available'
      });
    }

    let cart = await Cart.findOne({ user: req.user.id });

    if (!cart) {
      cart = new Cart({
        user: req.user.id,
        items: []
      });
    }

    const itemIndex = cart.items.findIndex(
      item => item.product.toString() === productId
    );

    if (itemIndex > -1) {
      cart.items[itemIndex].quantity += quantity;
    } else {
      cart.items.push({
        product: productId,
        quantity,
        price: product.price
      });
    }

    await cart.save();

    res.status(200).json({
      success: true,
      message: 'Item added to cart',
      cart
    });
  } catch (err) {
    handleError(res, err, 'Add to cart');
  }
});

// Update cart item quantity
app.put('/cart/:itemId', authenticateToken, async (req, res) => {
  try {
    const { quantity } = req.body;
    const { itemId } = req.params;

    const cart = await Cart.findOne({ user: req.user.id });
    if (!cart) {
      return res.status(404).json({
        success: false,
        message: 'Cart not found'
      });
    }

    const itemIndex = cart.items.findIndex(
      item => item._id.toString() === itemId
    );

    if (itemIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'Item not found in cart'
      });
    }

    const product = await Product.findById(cart.items[itemIndex].product);
    if (product.stock < quantity) {
      return res.status(400).json({
        success: false,
        message: 'Not enough stock available'
      });
    }

    cart.items[itemIndex].quantity = quantity;
    await cart.save();

    res.status(200).json({
      success: true,
      message: 'Cart updated',
      cart
    });
  } catch (err) {
    handleError(res, err, 'Update cart');
  }
});

// Remove item from cart
app.delete('/cart/:itemId', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;

    const cart = await Cart.findOne({ user: req.user.id });
    if (!cart) {
      return res.status(404).json({
        success: false,
        message: 'Cart not found'
      });
    }

    cart.items = cart.items.filter(
      item => item._id.toString() !== itemId
    );

    await cart.save();

    res.status(200).json({
      success: true,
      message: 'Item removed from cart',
      cart
    });
  } catch (err) {
    handleError(res, err, 'Remove from cart');
  }
});

// Clear cart
app.delete('/cart', authenticateToken, async (req, res) => {
  try {
    await Cart.findOneAndDelete({ user: req.user.id });

    res.status(200).json({
      success: true,
      message: 'Cart cleared'
    });
  } catch (err) {
    handleError(res, err, 'Clear cart');
  }
});

// Order Routes

// Create order
app.post('/orders', authenticateToken, async (req, res) => {
  try {
    const { shippingAddressId, paymentMethod } = req.body;

    // Get user's cart
    const cart = await Cart.findOne({ user: req.user.id }).populate('items.product');
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No items in cart'
      });
    }

    // Verify shipping address
    const address = await Address.findOne({ 
      _id: shippingAddressId, 
      userId: req.user.id 
    });
    if (!address) {
      return res.status(404).json({
        success: false,
        message: 'Address not found'
      });
    }

    // Calculate total price
    const items = cart.items.map(item => ({
      product: item.product._id,
      quantity: item.quantity,
      price: item.price
    }));

    const totalPrice = cart.items.reduce(
      (sum, item) => sum + (item.price * item.quantity), 0
    );

    // Check product stock
    for (const item of cart.items) {
      const product = await Product.findById(item.product._id);
      if (product.stock < item.quantity) {
        return res.status(400).json({
          success: false,
          message: `Not enough stock for ${product.name}`
        });
      }
    }

    // Create order
    const order = new Order({
      user: req.user.id,
      items,
      shippingAddress: shippingAddressId,
      paymentMethod,
      totalPrice
    });

    // Update product stock
    for (const item of cart.items) {
      await Product.findByIdAndUpdate(item.product._id, {
        $inc: { stock: -item.quantity }
      });
    }

    // Clear cart
    await Cart.findByIdAndDelete(cart._id);

    await order.save();

    res.status(201).json({
      success: true,
      message: 'Order created successfully',
      order
    });
  } catch (err) {
    handleError(res, err, 'Create order');
  }
});

// Get user's orders
app.get('/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user.id })
      .populate('items.product')
      .populate('shippingAddress')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      orders
    });
  } catch (err) {
    handleError(res, err, 'Get orders');
  }
});

// Get order details
app.get('/orders/:orderId', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.orderId,
      user: req.user.id
    })
    .populate('items.product')
    .populate('shippingAddress');

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.status(200).json({
      success: true,
        order
    });
  } catch (err) {
    handleError(res, err, 'Get order');
  }
});

// Cancel order
app.put('/orders/:orderId/cancel', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.orderId,
      user: req.user.id,
      status: { $in: ['processing', 'pending'] }
    });

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found or cannot be cancelled'
      });
    }

    // Restock products
    for (const item of order.items) {
      await Product.findByIdAndUpdate(item.product, {
        $inc: { stock: item.quantity }
      });
    }

    order.status = 'cancelled';
    await order.save();

    res.status(200).json({
      success: true,
      message: 'Order cancelled',
      order
    });
  } catch (err) {
    handleError(res, err, 'Cancel order');
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    message: 'Endpoint not found' 
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  handleError(res, err, 'Unhandled');
});

// Start the server
const server = app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});