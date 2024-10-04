import { Box, Heading, Button } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const Help = () => {
  const [data, setData] = useState('');

  useEffect(() => {
    axios.get('http://localhost:5000/help').then(response => {
      setData(response.data);
    });
  }, []);

  return (
    <Box p={5}>
      <Heading mb={4}>Help Page</Heading>
      <p>{data}</p>

      <Button colorScheme="blue" mt={4}>
        <Link to="/home">Go to Home</Link>
      </Button>
    </Box>
  );
};

export default Help;
