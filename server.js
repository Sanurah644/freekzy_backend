import express from 'express';
import cors from 'cors';
import passport from 'passport';
import { Strategy as DiscordStrategy } from 'passport-discord';
import session from 'express-session';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(session({ secret: 'super-secret-key', resave: false, saveUninitialized: false }));

passport.use(new DiscordStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.REDIRECT_URI,
  scope: ['identify', 'guilds', 'guilds.members.read']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const guildId = process.env.GUILD_ID;
    const userId = profile.id;

    const res = await axios.get(`https://discord.com/api/v10/guilds/${guildId}/members/${userId}`, {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` }
    });

    const roles = res.data.roles;
    const hasRole = roles.includes(process.env.ROLE_MEMBRE);

    return done(null, { userId, authorized: hasRole });
  } catch (error) {
    console.error('❌ Erreur API Discord :', error);
    return done(null, { userId: profile.id, authorized: false });
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/callback', passport.authenticate('discord', { failureRedirect: '/' }), (req, res) => {
  res.json({ authorized: req.user.authorized });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Serveur démarré sur le port ${PORT}`));
