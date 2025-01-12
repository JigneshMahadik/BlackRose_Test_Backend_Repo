// import logo from './logo.svg';
import './App.css';
import LoginPage from './Components/LoginPage';
import RandomNumberGenerator from './Components/RandomNumberGenerator';
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

function App() {
  return (
    <div className="App">
      {/* <RandomNumberGenerator/> */}
      <Router>
        <Routes>
          <Route path="/" element={<LoginPage />} />
          <Route path='/random' element={<RandomNumberGenerator />} />
        </Routes>
      </Router>

    </div>
  );
}

export default App;
