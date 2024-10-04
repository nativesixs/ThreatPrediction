import { Box, Heading, Button, Spinner } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const Help = ({ socket }) => {
  const [data, setData] = useState('');
  const [loading, setLoading] = useState(true); // Track loading state
  const [error, setError] = useState(''); // Track error state

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/help');
        setData(response.data);
      } catch (err) {
        console.error('Error fetching help data:', err);
        setError('Failed to fetch data from the server.');
      } finally {
        setLoading(false); // Loading finished
      }
    };

    fetchData();

    // Emit message to the socket
    socket.emit('message', { data: 'Hello from Help!' });

    return () => {
      // Clean up any socket listeners if necessary
    };
  }, [socket]);

  return (
    <Box p={5}>
      <Heading mb={4}>Help Page</Heading>
      {loading ? (
        <Spinner /> // Show a loading spinner while data is loading
      ) : error ? (
        <p>{error}</p> // Display error message if there was an error
      ) : (
        <p>{data}</p> // Show data when loaded successfully
      )}
      <Button colorScheme="blue" mt={4}>
        <Link to="/home">Go to Home</Link>
      </Button>
    </Box>
  );
};

export default Help;
