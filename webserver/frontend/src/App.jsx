import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Step1 from "./pages/Step1.jsx";
import Step2 from "./pages/Step2.jsx";
import Step3 from "./pages/Step3.jsx";
import Review from "./pages/Review.jsx";

export default function App() {
  return (
    <div style={{ maxWidth: 720, margin: "40px auto", padding: 16, fontFamily: "system-ui" }}>
      <h1>Wizard Runner</h1>
      <Routes>
        <Route path="/" element={<Navigate to="/step/1" replace />} />
        <Route path="/step/1" element={<Step1 />} />
        <Route path="/step/2" element={<Step2 />} />
        <Route path="/step/3" element={<Step3 />} />
        <Route path="/review" element={<Review />} />
        <Route path="*" element={<div>Not found</div>} />
      </Routes>
    </div>
  );
}
