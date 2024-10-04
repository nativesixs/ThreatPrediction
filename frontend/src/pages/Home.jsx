import { Box, Heading, Button } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const Home = ({ socket }) => {
  const [data, setData] = useState('');
  const [times, setTimes] = useState([]); // State to hold the times

  useEffect(() => {
    // Fetch initial data from the server
    const fetchData = async () => {
      const response = await fetch('http://localhost:5000/home');
      const result = await response.text(); // Get the response as text
      setData(result); // Set the initial data
    };

    fetchData();

    // Emit a request to start sending the current time
    socket.emit('request_time');

    // Listen for 'time' events from the server
    socket.on('time', (data) => {
      // Update times state and keep the latest time at the end
      setTimes(prevTimes => [...prevTimes, data.time]); // Update times state
    });

    // Handle completion message
    socket.on('complete', (data) => {
      console.log(data.data); // Log completion message
    });

    return () => {
      // Cleanup on component unmount
      socket.off('time'); // Cleanup the listener on component unmount
      socket.off('complete');

      // Reset times state to start fresh when navigating back
      setTimes([]); // Resetting the times
    };
  }, [socket]); // Re-run effect if socket changes

  // Get the latest time from the times array, if available
  const latestTime = times[times.length - 1];

  return (
    <Box p={5}>
      <Heading mb={4}>Home Page</Heading>
      <p>{data}</p>

      {/* Display the latest time as a single element */}
      <p style={{ fontSize: '24px', fontWeight: 'bold' }}>
        Current Time: {latestTime || 'Waiting for time...'}
      </p>

      <h3>Received Times:</h3>
      <ul>
        {times.map((time, index) => (
          <li key={index}>{time}</li> // Display each time in a list
        ))}
      </ul>

      <Button colorScheme="teal" mt={4}>
        <Link to="/help">Go to Help</Link>
      </Button>
    </Box>
  );
};

export default Home;
