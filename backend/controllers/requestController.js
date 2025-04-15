const Request = require('../models/Request');
const sendEmail = require('../utils/sendEmail');

// Create new request
exports.createRequest = async (req, res) => {
  try {
    const { subject, description, attachments } = req.body;
    
    const requestData = {
      subject,
      description,
      user: req.user.id
    };

    if (attachments && attachments.length > 0) {
      requestData.attachments = attachments;
    }

    const request = await Request.create(requestData);

    res.status(201).json({
      success: true,
      data: request
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get all requests (admin only)
exports.getAllRequests = async (req, res) => {
  try {
    const requests = await Request.find()
      .populate('user', 'name email')
      .populate('remarksHistory.createdBy', 'name')
      .sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      data: requests
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get user's requests
exports.getUserRequests = async (req, res) => {
  try {
    const requests = await Request.find({ user: req.user.id })
      .populate('remarksHistory.createdBy', 'name')
      .sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      data: requests
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update request status and remarks
exports.updateRequestStatus = async (req, res) => {
  try {
    const { status, remark } = req.body;
    const id = req.params.id;

    // Find request and populate user and admin details
    const request = await Request.findById(id)
      .populate('user', 'email name')
      .populate('adminActionBy', 'name');

    if (!request) {
      return res.status(404).json({ message: 'Request not found' });
    }

    // Add new remark to history
    if (remark) {
      request.remarksHistory.push({
        remark,
        createdAt: new Date(),
        createdBy: req.user._id
      });
    }

    // Update status if provided
    if (status) {
      request.status = status;
      request.adminActionDate = new Date();
      request.adminActionBy = req.user._id;

      // Send email notification
      const statusColor = status === 'approved' ? '#34C759' : status === 'rejected' ? '#FF3737' : '#FFC107';
      const emailSubject = `Request ${status.charAt(0).toUpperCase() + status.slice(1)}`;
      const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="margin: 20px 0; padding: 15px; border-left: 4px solid ${statusColor}; background-color: #f5f5f5;">
            <h2 style="margin: 0; color: #333;">Request Status Update</h2>
            <p style="margin: 10px 0 0 0;">
              Your request has been <strong style="color: ${statusColor}">${status}</strong>.
            </p>
          </div>
          
          ${remark ? `
          <div style="margin: 20px 0;">
            <h3 style="color: #666; margin-bottom: 10px;">Admin Remarks:</h3>
            <div style="padding: 15px; background-color: #fff; border: 1px solid #ddd; border-radius: 4px;">
              ${remark}
            </div>
          </div>
          ` : ''}
          
          <div style="margin: 20px 0;">
            <h3 style="color: #666; margin-bottom: 10px;">Request Details:</h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
              <tr>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;"><strong>Request ID:</strong></td>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;">${request.requestId}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;"><strong>Subject:</strong></td>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;">${request.subject}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;"><strong>Description:</strong></td>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;">${request.description}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;"><strong>Status:</strong></td>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;">
                  <span style="color: ${statusColor}; font-weight: bold;">${status.toUpperCase()}</span>
                </td>
              </tr>
              <tr>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;"><strong>Updated On:</strong></td>
                <td style="padding: 12px; border-bottom: 1px solid #ddd;">${new Date().toLocaleString()}</td>
              </tr>
            </table>
          </div>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p style="margin: 0;">Best regards,<br>Request Portal Admin</p>
          </div>
        </div>
      `;

      try {
        await sendEmail({
          email: request.user.email,
          subject: emailSubject,
          html: emailHtml,
          cc: 'vamsidharareddy.alam_2026@woxsen.edu.in'
        });
      } catch (emailError) {
        console.error('Error sending email:', emailError);
        // Continue even if email fails
      }
    }

    await request.save();

    // Fetch the updated request with populated fields
    const updatedRequest = await Request.findById(id)
      .populate('user', 'name email')
      .populate('remarksHistory.createdBy', 'name')
      .populate('adminActionBy', 'name');

    res.status(200).json({
      success: true,
      data: updatedRequest
    });
  } catch (error) {
    console.error('Error updating request:', error);
    res.status(500).json({ success: false, message: error.message });
  }
};
