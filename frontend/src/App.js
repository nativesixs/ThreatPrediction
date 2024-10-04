import React, { useEffect } from 'react';
import { ChakraProvider } from '@chakra-ui/react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Home from './pages/Home';
import Help from './pages/Help';
import { io } from 'socket.io-client';

const socket = io('http://localhost:5000');

const App = () => {
  useEffect(() => {
    socket.on('response', (data) => {
      console.log(data);
    });

    return () => {
      socket.off('response');
    };
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/home" />} />
        <Route path="/home" element={<Home socket={socket} />} />
        <Route path="/help" element={<Help socket={socket} />} />
      </Routes>
    </Router>
  );
};

export default App;
