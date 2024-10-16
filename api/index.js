require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const User = require('../models/user');
const Card = require('../models/card');
const Group = require('../models/group');
const Message = require('../models/message');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.set('strictQuery', true);

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const corsOptions = {
  origin: 'https://maxgudinovich.github.io',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};

app.use(cors(corsOptions));

const refreshTokens = [];

const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (authHeader) {
    const token = authHeader.replace('Bearer ', '');
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

const sendSystemMessageToAll = async (title, body) => {
  try {
    const allUsers = await User.find({}, '_id');

    const userIds = allUsers.map((user) => user._id);

    const message = new Message({
      title,
      body,
      userIds,
    });

    await message.save();
  } catch (error) {
    console.error('Error sending system message to all users:', error);
    throw error;
  }
};

const generateRefreshToken = (user) => {
  return jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: '10d' });
};

const generateAccessToken = (user) => {
  return jwt.sign(user, JWT_SECRET, { expiresIn: '10m' });
};

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    const token = generateAccessToken({
      id: newUser._id,
      username: newUser.username,
      role: newUser.role,
    });
    const refreshToken = generateRefreshToken({
      id: newUser._id,
      username: newUser.username,
      role: newUser.role,
    });
    refreshTokens.push(refreshToken);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
    });

    res.json({ token, refreshToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/register-admin', async (req, res) => {
  const { username, password, secretKey } = req.body;

  if (secretKey !== process.env.SECRET_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = new User({
      username,
      password: hashedPassword,
      role: 'admin',
    });
    await newUser.save();
    const token = generateAccessToken({
      id: newUser._id,
      username: newUser.username,
      role: newUser.role,
    });
    const refreshToken = generateRefreshToken({
      id: newUser._id,
      username: newUser.username,
      role: newUser.role,
    });
    refreshTokens.push(refreshToken);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
    });

    // Возврат обоих токенов в ответе
    res.json({ token, refreshToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '10m' }
      );
      const refreshToken = generateRefreshToken({
        id: user._id,
        username: user.username,
        role: user.role,
      });
      refreshTokens.push(refreshToken); // Добавление рефреш токена в массив или хранилище

      // Установка рефреш токена в HTTP-only cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
      });

      // Возврат обоих токенов в ответе
      res.json({ token, refreshToken });
    } else {
      res.status(400).json({ error: 'Invalid username or password' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/token', (req, res) => {
  const refreshToken =
    req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not found' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    const accessToken = generateAccessToken({
      id: decoded.id,
      username: decoded.username,
      role: decoded.role,
    });
    const newRefreshToken = generateRefreshToken({
      id: decoded.id,
      username: decoded.username,
      role: decoded.role,
    });

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    console.error(err);
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

app.post('/groups', authenticateJWT, async (req, res) => {
  const { groupName } = req.body;

  if (!groupName) {
    return res.status(400).json({ error: 'groupName is required' });
  }

  try {
    const userId = req.user.id;

    let group = await Group.findOne({ groupName, createdBy: userId });

    if (!group) {
      group = new Group({ groupName, createdBy: userId });
    }

    await group.save();

    res.status(201).json(group);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/cards', authenticateJWT, async (req, res) => {
  const { word, translate, groupName, description, groupId } = req.body;

  if (!word || !translate || !groupName || !groupId) {
    return res
      .status(400)
      .json({ error: 'Word, translate, groupName, and groupId are required' });
  }

  try {
    const isAdmin = req.user.role === 'admin';
    const userId = req.user.id;

    let group;

    // Если администратор, находим группу по ID
    if (isAdmin) {
      group = await Group.findOne({ _id: groupId });
    } else {
      // Если не администратор, находим группу по имени и ID пользователя
      group = await Group.findOne({ groupName, createdBy: userId });
    }

    // Если группа не найдена
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    // Создаем новую карточку
    const newCard = new Card({
      word,
      translate,
      description,
      createdBy: userId,
    });

    // Добавляем ID карточки в массив карт группы
    group.cards.push(newCard._id);

    // Сохраняем карточку и группу
    await newCard.save();
    await group.save();

    res.status(201).json(newCard);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/cards/:id', authenticateJWT, async (req, res) => {
  const { word, translate, description } = req.body;

  if (!word || !translate) {
    return res.status(400).json({ error: 'Word and translate are required' });
  }

  try {
    const admin = req.user.role === 'admin';
    const userId = req.user.id;
    let card;

    if (admin) {
      card = await Card.findOne({ _id: req.params.id });
    } else {
      card = await Card.findOne({ _id: req.params.id, createdBy: userId });
    }

    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    card.word = word;
    card.translate = translate;
    card.description = description;

    await card.save();

    res.json(card);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/cards', authenticateJWT, async (req, res) => {
  try {
    const cards = await Card.find({ createdBy: req.user.id });
    res.json(cards);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/cards/:id', authenticateJWT, async (req, res) => {
  try {
    const admin = req.user.role === 'admin';
    const userId = req.user.id;
    let card;
    if (admin) {
      card = await Card.findOne({ _id: req.params.id });
    } else {
      card = await Card.findOne({ _id: req.params.id, createdBy: userId });
    }
    res.json(card);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/groups', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const groups = await Group.find({ createdBy: userId }).populate('cards');
    console.log('user id:', userId);
    console.log(req.user);
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/groups-all', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const groups = await Group.find().populate('cards');
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/groups/:id', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const groupId = req.params.id;
    const isAdmin = req.user.role === 'admin';

    console.log('Deleting group with ID:', groupId, 'by user ID:', userId);

    let group;

    if (isAdmin) {
      // Если пользователь администратор, удаляем группу по ID
      group = await Group.findOneAndDelete({
        _id: groupId,
      });
    } else {
      // Если пользователь не администратор, удаляем группу, созданную этим пользователем
      group = await Group.findOneAndDelete({
        createdBy: userId,
        _id: groupId,
      });
    }

    if (!group) {
      return res.status(404).json({
        error: 'Group not found or you do not have permission to delete it',
      });
    }

    res.json({ message: 'Group was deleted successfully', group });
  } catch (err) {
    console.error('Error deleting group:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/groups/:id', authenticateJWT, async (req, res) => {
  try {
    const admin = req.user.role === 'admin';
    const userId = req.user.id;
    let group;

    if (admin) {
      group = await Group.findOne({
        _id: req.params.id,
      }).populate('cards');
    } else {
      group = await Group.findOne({
        createdBy: userId,
        _id: req.params.id,
      }).populate('cards');
    }

    res.json(group);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/protected', authenticateJWT, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

app.post('/messages', authenticateJWT, async (req, res) => {
  const { title, body } = req.body;

  if (!title || !body) {
    return res.status(400).json({ error: 'Title and body are required' });
  }

  try {
    await sendSystemMessageToAll(title, body);
    res.status(201).json({ message: 'Message sent successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/messages', authenticateJWT, async (req, res) => {
  try {
    const messages = await Message.find(
      { userIds: req.user.id },
      { userIds: 0 }
    );
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
