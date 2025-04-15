const express = require('express');
const router = express.Router();
const {
  createRequest,
  getAllRequests,
  getUserRequests,
  updateRequestStatus
} = require('../controllers/requestController');
const { protect, authorize } = require('../middleware/auth');

router.post('/', protect, createRequest);
router.get('/me', protect, getUserRequests);
router.get('/all', protect, authorize('admin'), getAllRequests);
router.put('/:id', protect, authorize('admin'), updateRequestStatus);

module.exports = router;
