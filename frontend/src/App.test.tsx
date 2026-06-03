import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

test('renders ncert reader heading', () => {
  render(<App />);
  const heading = screen.getByText(/NCERT Reader/i);
  expect(heading).toBeInTheDocument();
});
