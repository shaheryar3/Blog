import React from 'react';
import { Button } from 'react-bootstrap';

interface BottomNavProps {
  onHome: () => void;
  onContinue: () => void;
  disableContinue: boolean;
}

const BottomNav: React.FC<BottomNavProps> = ({ onHome, onContinue, disableContinue }) => {
  return (
    <div className="bottom-nav">
      <Button variant="light" onClick={onHome} className="bottom-nav-button">Home</Button>
      <Button variant="primary" onClick={onContinue} disabled={disableContinue} className="bottom-nav-button">
        Continue
      </Button>
    </div>
  );
};

export default BottomNav;
