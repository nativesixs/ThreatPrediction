import { Box, Heading, Button } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const Home = ({ socket }) => {
  const [data, setData] = useState('');
  const [times, setTimes] = useState([]); // State to hold the times
  const [traffic, setTraffic] = useState([]); // State to hold network traffic

  useEffect(() => {
    // Fetch initial data from the server
    const fetchData = async () => {
      const response = await fetch('http://localhost:5000/home');
      const result = await response.text(); // Get the response as text
      setData(result); // Set the initial data
    };

    fetchData();

    // Emit a request to start sending the current time and traffic
    socket.emit('request_time');

    // Listen for 'time' events from the server
    socket.on('time', (data) => {
      // Update times state and keep the latest time at the end
      setTimes(prevTimes => [...prevTimes, data.time]); // Update times state
    });

    // Listen for 'traffic' events from the server
    socket.on('traffic', (data) => {
      // Update traffic state with the new traffic data
      setTraffic(prevTraffic => [...prevTraffic, data.traffic]);
    });

    // Handle completion message
    socket.on('complete', (data) => {
      console.log(data.data); // Log completion message
    });

    return () => {
      // Cleanup on component unmount
      socket.off('time'); // Cleanup the listener on component unmount
      socket.off('traffic'); // Cleanup the traffic listener
      socket.off('complete');

      // Reset states to start fresh when navigating back
      setTimes([]); // Resetting the times
      setTraffic([]); // Resetting the traffic data
    };
  }, [socket]); // Re-run effect if socket changes

  // Get the latest time from the times array, if available
  const latestTime = times[times.length - 1];

  // Function to reset the times array
  const resetTime = () => {
    setTimes([]); // Clear the times array
  };

  // Function to reset the traffic array
  const resetTraffic = () => {
    setTraffic([]); // Clear the traffic array
  };

  return (
    <Box p={5}>
      <Heading mb={4}>Home Page</Heading>
      <p>{data}</p>
      <Button onClick={resetTime} colorScheme='teal' mt={4}>
        Reset Times
      </Button>
      <Button onClick={resetTraffic} colorScheme='teal' mt={4}>
        Reset Traffic
      </Button>

      {/* Display the latest time as a single element */}
      <p style={{ fontSize: '24px', fontWeight: 'bold' }}>
        Current Time: {latestTime || 'Waiting for time...'}
      </p>

      <Button colorScheme="teal" mt={4}>
        <Link to="/help">Go to Help</Link>
      </Button>

      <h3>Received Times:</h3>
      <ul>
        {times.map((time, index) => (
          <li key={index}>{time}</li> // Display each time in a list
        ))}
      </ul>

      <h3>Network Traffic:</h3>
      <ul>
        {traffic.map((trafficData, index) => (
          <li key={index}>{trafficData}</li> // Display each traffic entry in a list
        ))}
      </ul>
    </Box>
  );
};

export default Home;
