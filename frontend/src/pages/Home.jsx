import { Box, Heading, Button } from '@chakra-ui/react';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const Home = () => {
  const [data, setData] = useState('');

  useEffect(() => {
    axios.get('http://localhost:5000/home').then(response => {
      setData(response.data);
    });
  }, []);

  return (
    <Box p={5}>
      <Heading mb={4}>Home Page</Heading>
      <p>{data}</p>

      <Button colorScheme="teal" mt={4}>
        <Link to="/help">Go to Help</Link>
      </Button>
    </Box>
  );
};

export default Home;
