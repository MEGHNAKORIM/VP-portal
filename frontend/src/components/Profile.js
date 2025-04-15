import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Avatar,
  Button,
  Menu,
  MenuItem,
  Divider,
  List,
  ListItem,
  ListItemText,
  IconButton
} from '@mui/material';
import { AccountCircle, Email, Phone, School } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Profile = () => {
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);

  const handleMenu = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  if (!user) {
    return null;
  }

  return (
    <Box sx={{ position: 'relative' }}>
      <IconButton
        size="large"
        onClick={handleMenu}
        color="inherit"
      >
        <AccountCircle />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        <Box sx={{ p: 2, width: 320 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Avatar sx={{ width: 60, height: 60, bgcolor: 'primary.main' }}>
              {user.name?.charAt(0).toUpperCase()}
            </Avatar>
            <Box sx={{ ml: 2 }}>
              <Typography variant="h6">{user.name}</Typography>
              <Typography variant="body2" color="textSecondary">
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </Typography>
            </Box>
          </Box>
          <Divider />
          <List dense>
            <ListItem>
              <Email sx={{ mr: 2, color: 'primary.main' }} />
              <ListItemText 
                primary="Email"
                secondary={user.email}
              />
            </ListItem>
            <ListItem>
              <School sx={{ mr: 2, color: 'primary.main' }} />
              <ListItemText 
                primary="School"
                secondary={user.school}
              />
            </ListItem>
            <ListItem>
              <Phone sx={{ mr: 2, color: 'primary.main' }} />
              <ListItemText 
                primary="Phone"
                secondary={user.phone}
              />
            </ListItem>
          </List>
          <Divider />
          <Box sx={{ mt: 2, textAlign: 'center' }}>
            <Button
              variant="contained"
              color="primary"
              fullWidth
              onClick={handleLogout}
            >
              Logout
            </Button>
          </Box>
        </Box>
      </Menu>
    </Box>
  );
};

export default Profile;
