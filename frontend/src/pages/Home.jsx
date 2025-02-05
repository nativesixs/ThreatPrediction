import { Box, Heading, Button } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const Home = ({ socket }) => {
  const [data, setData] = useState('');
  const [times, setTimes] = useState([]);
  const [traffic, setTraffic] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const response = await fetch('http://localhost:5000/home');
      const result = await response.text();
      setData(result);
    };

    fetchData();

    socket.on('time', (data) => {
      setTimes(prevTimes => [...prevTimes, data.time]);
    });

    socket.on('traffic', (data) => {
      setTraffic(prevTraffic => [...prevTraffic, data.traffic]);
    });

    socket.on('complete', (data) => {
      console.log(data.data);
      setTraffic(prevTraffic => [...prevTraffic, data.data]);
    });

    return () => {
      socket.off('time');
      socket.off('traffic');
      socket.off('complete');

      setTimes([]);
      setTraffic([]);
    };
  }, [socket]);

  const latestTime = times[times.length - 1];

  const resetTime = () => {
    setTimes([]);
  };

  const resetTraffic = () => {
    setTraffic([]);
  };

  const startTime = () => {
    socket.emit('request_time');
  };

  const stopTime = () => {
    socket.emit('stop_time');
  };

  const startSniffing = () => {
    socket.emit('start_sniffing');
  };

  const stopSniffing = () => {
    socket.emit('stop_sniffing');
  };

  const resetSniffing = () => {
    resetTraffic();
    socket.emit('reset_sniffing');
  };

  return (
    <Box p={5}>
      <Heading mb={4}>Home Page</Heading>
      <p>{data}</p>

      <Button onClick={startTime} colorScheme="teal" mt={4}>
        Start Time
      </Button>
      <Button onClick={stopTime} colorScheme="red" mt={4}>
        Stop Time
      </Button>
      <Button onClick={startSniffing} colorScheme="teal" mt={4}>
        Start Sniffing
      </Button>
      <Button onClick={stopSniffing} colorScheme="red" mt={4}>
        Stop Sniffing
      </Button>
      <Button onClick={resetTime} colorScheme='teal' mt={4}>
        Reset Time
      </Button>
      <Button onClick={resetSniffing} colorScheme="teal" mt={4}>
        Reset Sniffing
      </Button>

      {/* Display the latest time as a single element */}
      <p style={{ fontSize: '24px', fontWeight: 'bold' }}>
        Current Time: {latestTime || 'Waiting for time...'}
      </p>

      {/* Go to Help Button */}
      <Button colorScheme="teal" mt={4}>
        <Link to="/help">Go to Help</Link>
      </Button>

      <h3>Received Times:</h3>
      <ul>
        {times.map((time, index) => (
          <li key={index}>{time}</li>
        ))}
      </ul>

      <h3>Network Traffic:</h3>
      <ul>
        {traffic.map((trafficData, index) => (
          <li key={index}>{trafficData}</li>
        ))}
      </ul>
    </Box>
  );
};

export default Home;
