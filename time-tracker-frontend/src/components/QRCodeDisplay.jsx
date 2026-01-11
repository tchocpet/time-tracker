import React, { useState, useEffect } from "react";
import axios from "axios";
import API from '../services/api';

const QRCodeDisplay = () => {
    const [qrCode, setQrCode] = useState("");

    useEffect(() => {
        const fetchQRCode = async () => {
            try {
                const response = await API.get('/generate-qr');
                setQrCode(response.data.qrCode);
            } catch (error) {
                console.error("Error fetching QR Code:", error);
            }
        };

        fetchQRCode();
    }, []);

    return (
        <div>
            <h2>Scan the QR Code to Log Work Hours</h2>
            {qrCode ? <img src={qrCode} alt="General QR Code" /> : <p>Loading QR Code...</p>}
        </div>
    );
};

export default QRCodeDisplay;
