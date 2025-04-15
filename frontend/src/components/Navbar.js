import {React ,useState}from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
} from '@mui/material';
import { useAuth } from '../context/AuthContext';
import Profile from './Profile';

const Navbar = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);

  const handleMenu = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography 
          variant="h6" 
          component="div" 
          sx={{ 
            flexGrow: 1, 
            cursor: 'pointer',
            '&:hover': { opacity: 0.8 } 
          }}
          onClick={() => navigate('/')}
        >
          Request Portal
        </Typography>
        {user ? (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {user.role === 'admin' ? (
              <Button 
                color="inherit" 
                variant="outlined"
                onClick={() => navigate('/admin')}
                sx={{ borderColor: 'rgba(255,255,255,0.5)' }}
              >
                Admin Dashboard
              </Button>
            ) : (
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button 
                  color="inherit"
                  variant="outlined"
                  onClick={() => navigate('/dashboard')}
                  sx={{ borderColor: 'rgba(255,255,255,0.5)' }}
                >
                  My Requests
                </Button>
                <Button 
                  color="inherit"
                  variant="contained"
                  onClick={() => navigate('/create-request')}
                  sx={{ bgcolor: 'primary.dark' }}
                >
                  New Request
                </Button>
              </Box>
            )}
            <Profile />
          </Box>
        ) : (
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button 
              color="inherit"
              variant="outlined"
              onClick={() => navigate('/login')}
              sx={{ borderColor: 'rgba(255,255,255,0.5)' }}
            >
              Login
            </Button>
            <Button 
              color="inherit"
              variant="contained"
              onClick={() => navigate('/register')}
              sx={{ bgcolor: 'primary.dark' }}
            >
              Register
            </Button>
          </Box>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
