// index.js - Servidor principal do painel
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'automatizaria-secret-key-2024';

// Middleware de segurança
app.use(helmet({
  contentSecurityPolicy: false // Permitir inline scripts para o dashboard
}));
app.use(compression());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // máximo 100 requests por IP
});
app.use(limiter);

// Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Simulação de banco de dados (em produção, use MongoDB/PostgreSQL)
const users = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@automatizaria.com.br',
    password: '$2b$10$example', // 'admin123' hasheada
    role: 'admin',
    name: 'Administrador'
  },
  {
    id: 2,
    username: 'cliente1',
    email: 'cliente1@empresa.com',
    password: '$2b$10$example', // 'cliente123' hasheada
    role: 'client',
    name: 'Cliente Exemplo',
    clientId: 'client_001'
  }
];

const agents = [
  {
    id: 'agent_001',
    name: 'Atendente Virtual - Loja XYZ',
    clientId: 'client_001',
    status: 'active',
    phone: '5521999999999',
    messagesCount: 1247,
    conversationsCount: 89,
    hoursWorked: 168.5,
    economyValue: 2530.75,
    createdAt: new Date('2024-01-15')
  }
];

const metrics = [
  {
    agentId: 'agent_001',
    date: new Date().toISOString().split('T')[0],
    messagesReceived: 45,
    messagesSent: 42,
    conversationsStarted: 8,
    conversationsFinished: 6,
    avgResponseTime: 2.3, // segundos
    customerSatisfaction: 4.2 // de 1 a 5
  }
];

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Middleware de autorização por role
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
  };
};

// Rota principal - Dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    // Em produção, use bcrypt.compare
    const validPassword = password === 'admin123' && user.username === 'admin' || 
                          password === 'cliente123' && user.username === 'cliente1';
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        clientId: user.clientId 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
        role: user.role,
        clientId: user.clientId
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Dashboard do Admin
app.get('/api/admin/dashboard', authenticateToken, requireRole(['admin']), (req, res) => {
  const totalAgents = agents.length;
  const totalClients = users.filter(u => u.role === 'client').length;
  const totalMessages = agents.reduce((sum, agent) => sum + agent.messagesCount, 0);
  const totalEconomy = agents.reduce((sum, agent) => sum + agent.economyValue, 0);

  res.json({
    overview: {
      totalAgents,
      totalClients,
      totalMessages,
      totalEconomy,
      systemUptime: process.uptime()
    },
    recentAgents: agents.slice(0, 5),
    systemHealth: {
      cpu: Math.random() * 100,
      memory: Math.random() * 100,
      disk: Math.random() * 100
    }
  });
});

// Dashboard do Cliente
app.get('/api/client/dashboard', authenticateToken, requireRole(['client']), (req, res) => {
  const clientAgents = agents.filter(agent => agent.clientId === req.user.clientId);
  const totalMessages = clientAgents.reduce((sum, agent) => sum + agent.messagesCount, 0);
  const totalConversations = clientAgents.reduce((sum, agent) => sum + agent.conversationsCount, 0);
  const totalHours = clientAgents.reduce((sum, agent) => sum + agent.hoursWorked, 0);
  const totalEconomy = clientAgents.reduce((sum, agent) => sum + agent.economyValue, 0);

  res.json({
    overview: {
      totalAgents: clientAgents.length,
      totalMessages,
      totalConversations,
      totalHoursWorked: totalHours,
      totalEconomy
    },
    agents: clientAgents,
    monthlyStats: {
      messagesThisMonth: Math.floor(totalMessages * 0.3),
      conversationsThisMonth: Math.floor(totalConversations * 0.3),
      economyThisMonth: Math.floor(totalEconomy * 0.3)
    }
  });
});

// Métricas detalhadas do agente
app.get('/api/agent/:id/metrics', authenticateToken, (req, res) => {
  const agentId = req.params.id;
  const agent = agents.find(a => a.id === agentId);
  
  if (!agent) {
    return res.status(404).json({ error: 'Agente não encontrado' });
  }

  // Verificar permissão
  if (req.user.role === 'client' && agent.clientId !== req.user.clientId) {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const agentMetrics = metrics.filter(m => m.agentId === agentId);
  
  // Gerar dados dos últimos 30 dias
  const last30Days = [];
  for (let i = 29; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    last30Days.push({
      date: dateStr,
      messages: Math.floor(Math.random() * 50) + 10,
      conversations: Math.floor(Math.random() * 10) + 1,
      responseTime: (Math.random() * 5 + 1).toFixed(1),
      satisfaction: (Math.random() * 2 + 3).toFixed(1)
    });
  }

  res.json({
    agent,
    dailyMetrics: last30Days,
    summary: {
      avgDailyMessages: Math.floor(agent.messagesCount / 30),
      avgResponseTime: 2.3,
      customerSatisfaction: 4.2,
      uptime: 99.8
    }
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Integração com Evolution API (simulada)
app.get('/api/evolution/status', authenticateToken, (req, res) => {
  res.json({
    instances: [
      {
        name: 'cliente1-bot',
        status: 'connected',
        phone: '5521999999999',
        qrCode: null,
        lastSeen: new Date().toISOString()
      }
    ]
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

// 404 handler
app.use('*', (req, res) => {
  if (req.originalUrl.startsWith('/api/')) {
    res.status(404).json({ error: 'Endpoint não encontrado' });
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Painel Automatizaria rodando na porta ${port}`);
  console.log(`📊 Admin: admin / admin123`);
  console.log(`👤 Cliente: cliente1 / cliente123`);
  console.log(`🌐 Acesse: http://painel.automatizaria.com.br`);
});