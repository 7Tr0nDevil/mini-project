import React from 'react';
import { useNavigate } from 'react-router-dom';
import backgroundImage from '../assets/background.jpeg'; 
import './WelcomePage.css';

const WelcomePage = () => {
  const navigate = useNavigate();

  const handleClick = () => {
    navigate('/login');
  };

  return (
    <div
      className="welcome-container"
      style={{ backgroundImage: `url(${backgroundImage})` }} 
    >
      <h1>Welcome to Organ Hub</h1>
      <p>Join us in bridging the gap between hope and healing</p>
      <button className="welcome-button" onClick={handleClick}>🙌 Step into Hope</button>
    </div>
  );
};

export default WelcomePage;
