import React, { useEffect, useState, useRef } from "react";
import API from "../api";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";

export default function RecipientCertificate() {
  const [profile, setProfile] = useState(null);
  const [message, setMessage] = useState("Loading...");
  const certRef = useRef();

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const token = localStorage.getItem("token");
        const res = await API.get("/api/recipients/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setProfile(res.data);
        setMessage("");
      } catch (error) {
        console.error("Error fetching recipient data:", error);
        setMessage("Failed to load certificate.");
      }
    };
    fetchProfile();
  }, []);

  const handleDownload = async () => {
    const input = certRef.current;
    const canvas = await html2canvas(input);
    const imgData = canvas.toDataURL("image/png");
    const pdf = new jsPDF("p", "mm", "a4");
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = pdf.internal.pageSize.getHeight();
    pdf.addImage(imgData, "PNG", 0, 0, pdfWidth, pdfHeight);
    pdf.save(`recipient_certificate_${profile.name}.pdf`);
  };

  if (message) return <div className="container mt-5">{message}</div>;

  return (
    <div className="container mt-5">
      <div
        ref={certRef}
        style={{
          border: "10px solid gold",
          padding: "40px",
          textAlign: "center",
          backgroundColor: "#fffbe6",
          fontFamily: "serif",
          boxShadow: "0 0 20px rgba(0,0,0,0.2)",
        }}
      >
        <img
          src="/logo.png"
          alt="OrganHub"
          style={{ width: "150px", marginBottom: "20px" }}
        />
        <h1 style={{ color: "#d4af37", fontSize: "32px" }}>
          Recipient Confirmation
        </h1>
        <p style={{ fontSize: "18px", marginTop: "20px" }}>
          This confirms that
        </p>
        <h2
          style={{ fontWeight: "bold", fontSize: "28px", margin: "20px 0" }}
        >
          {profile.name}
        </h2>
        <p style={{ fontSize: "16px" }}>
          Is registered to receive {profile.organNeeded} under OrganHub’s
          matching program.
        </p>
        <div
          style={{ marginTop: "30px", textAlign: "left", fontSize: "14px" }}
        >
          <p><strong>Age:</strong> {profile.age}</p>
          <p><strong>Blood Type:</strong> {profile.bloodType}</p>
          <p><strong>Organ Needed:</strong> {profile.organNeeded}</p>
          <p><strong>Phone:</strong> {profile.phone_no}</p>
        </div>
        <p
          style={{ marginTop: "40px", fontStyle: "italic", fontSize: "16px" }}
        >
          We are committed to supporting your health journey.
        </p>
        <div
          style={{ marginTop: "60px", textAlign: "right", fontSize: "14px" }}
        >
          <p>________________________</p>
          <p>OrganHub Coordinator</p>
        </div>
      </div>

      <button className="btn btn-primary mt-3" onClick={handleDownload}>
        Download Certificate (PDF)
      </button>
    </div>
  );
}
