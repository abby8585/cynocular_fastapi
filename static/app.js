import React, { useState, useEffect } from 'react';
import axios from 'axios';

const App = () => {
  const [input, setInput] = useState('');
  const [fileHash, setFileHash] = useState('');
  const [url, setUrl] = useState('');
  const [ip, setIp] = useState('');
  const [domain, setDomain] = useState('');
  const [gptResult, setGptResult] = useState('');
  const [vtScanResult, setVtScanResult] = useState('');
  const [vtScanSummary, setVtScanSummary] = useState('');
  const [vtDnsResult, setVtDnsResult] = useState('');
  const [vtDnsSummary, setVtDnsSummary] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadResult, setUploadResult] = useState('');
  const [finalSummary, setFinalSummary] = useState('');
  const [error, setError] = useState('');

  const handleGptRequest = async () => {
    try {
      const response = await axios.post('/gpt', { text: input });
      setGptResult(response.data.result);
    } catch (error) {
      setError('Error fetching GPT-4 result.');
      console.error('Error fetching GPT-4 result:', error);
    }
  };

  const handleVtScanRequest = async () => {
    try {
      const response = await axios.post('/vt/scan', { fileHash, url, ip });
      setVtScanResult(JSON.stringify(response.data.result, null, 2));
      setVtScanSummary(response.data.summary || 'No summary available');
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setError('');
      }
    } catch (error) {
      setError('Error fetching VirusTotal scan result.');
      console.error('Error fetching VirusTotal scan result:', error);
    }
  };

  const handleVtDnsRequest = async () => {
    try {
      const response = await axios.post('/vt/dns', { domain });
      setVtDnsResult(JSON.stringify(response.data.result, null, 2));
      setVtDnsSummary(response.data.summary || 'No summary available');
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setError('');
      }
    } catch (error) {
      setError('Error fetching VirusTotal DNS result.');
      console.error('Error fetching VirusTotal DNS result:', error);
    }
  };

  const handleFileUpload = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const uploadFile = async () => {
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setUploadResult(JSON.stringify(response.data.metadata, null, 2));
      if (response.data.metadata_summary) {
        setGptResult(response.data.metadata_summary);
      }
      if (response.data.error) {
        setError(response.data.error);
      } else {
        setError('');
      }
    } catch (error) {
      setError('Error uploading file.');
      console.error('Error uploading file:', error);
    }
  };

  useEffect(() => {
    if (fileHash || url || ip) {
      handleVtScanRequest();
    }
  }, [fileHash, url, ip]);

  useEffect(() => {
    if (domain) {
      handleVtDnsRequest();
    }
  }, [domain]);

  useEffect(() => {
    if (vtScanResult || vtDnsResult || uploadResult) {
      const fetchFinalSummary = async () => {
        try {
          const response = await axios.post('/complete_summary', {
            file_metadata_summary: uploadResult,
            vt_scan_result: vtScanSummary,
            vt_dns_result: vtDnsSummary,
          });
          setFinalSummary(response.data.summary || 'No summary available');
        } catch (error) {
          setError('Error fetching final summary.');
          console.error('Error fetching final summary:', error);
        }
      };
      fetchFinalSummary();
    }
  }, [vtScanResult, vtDnsResult, uploadResult]);

  return (
    <div>
      <h1>React Integration with LangChain and VirusTotal</h1>

      <h2>GPT-4 Request</h2>
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Enter text"
      />
      <button onClick={handleGptRequest}>Get GPT-4 Result</button>
      <div>
        <h3>GPT-4 Result:</h3>
        <p>{gptResult}</p>
      </div>

      <h2>VirusTotal Scan</h2>
      <input
        type="text"
        value={fileHash}
        onChange={(e) => setFileHash(e.target.value)}
        placeholder="File Hash"
      />
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="URL"
      />
      <input
        type="text"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        placeholder="IP Address"
      />
      <input
        type="text"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="Domain"
      />
      <input type="file" onChange={handleFileUpload} />
      <button onClick={uploadFile}>Upload File</button>
      <div>
        <h3>VirusTotal Scan Result:</h3>
        <pre>{vtScanResult}</pre>
        <h3>VirusTotal Scan Summary:</h3>
        <p>{vtScanSummary}</p>
        <h3>VirusTotal DNS Result:</h3>
        <pre>{vtDnsResult}</pre>
        <h3>VirusTotal DNS Summary:</h3>
        <p>{vtDnsSummary}</p>
        <h3>Upload Result:</h3>
        <pre>{uploadResult}</pre>
      </div>

      <h2>Final Summary</h2>
      <div>
        <h3>Final Summary:</h3>
        <pre>{finalSummary}</pre>
      </div>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default App;
