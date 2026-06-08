import { useState, useCallback } from 'react';
import { 
  Upload as UploadIcon, 
  File, 
  X, 
  ShieldAlert, 
  Info,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { clsx } from 'clsx';

const Upload = () => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const navigate = useNavigate();

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('/api/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      // Navigate to queue after successful upload
      navigate('/queue');
    } catch (err: any) {
      console.error('Upload failed', err);
      setError(err.response?.data?.detail || 'Failed to upload file. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="flex-1 p-8 max-w-5xl mx-auto w-full space-y-8">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Submit Sample</h2>
        <p className="text-dark-400">Upload a suspicious file for behavioral and static analysis.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Upload Area */}
        <div className="lg:col-span-2 space-y-6">
          <div 
            className={clsx(
              "relative border-2 border-dashed rounded-2xl p-12 transition-all duration-300 flex flex-col items-center justify-center text-center",
              dragActive ? "border-primary-500 bg-primary-500/5" : "border-dark-800 bg-dark-900/30",
              file ? "border-success-500/50 bg-success-500/5" : "hover:border-dark-700 hover:bg-dark-900/50"
            )}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input 
              type="file" 
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" 
              onChange={handleChange}
            />
            
            {!file ? (
              <>
                <div className="w-20 h-20 bg-dark-800 rounded-full flex items-center justify-center mb-6 text-dark-400 group-hover:text-primary-500 transition-colors">
                  <UploadIcon size={40} />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">Drag and drop your file here</h3>
                <p className="text-dark-400 max-w-xs mx-auto">
                  Supported formats: PE, ELF, PDF, Office, Scripts, and more. (Max 100MB)
                </p>
                <button className="mt-8 px-8 py-3 bg-dark-800 text-white rounded-xl font-bold hover:bg-dark-700 transition-colors border border-dark-700">
                  Select File
                </button>
              </>
            ) : (
              <div className="w-full">
                <div className="flex items-center justify-between p-6 bg-dark-800 rounded-xl border border-dark-700 mb-8">
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 bg-primary-600/20 text-primary-500 rounded-lg flex items-center justify-center">
                      <File size={24} />
                    </div>
                    <div className="text-left">
                      <h4 className="font-bold text-white">{file.name}</h4>
                      <p className="text-xs text-dark-400">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                    </div>
                  </div>
                  <button 
                    onClick={(e) => { e.stopPropagation(); setFile(null); }}
                    className="p-2 hover:bg-dark-700 rounded-full text-dark-400 transition-colors"
                  >
                    <X size={20} />
                  </button>
                </div>
                
                <div className="flex gap-4">
                  <button 
                    onClick={handleUpload}
                    disabled={uploading}
                    className={clsx(
                      "flex-1 py-4 rounded-xl font-bold text-white transition-all flex items-center justify-center gap-2",
                      uploading ? "bg-dark-700 cursor-not-allowed" : "bg-primary-600 hover:bg-primary-700 shadow-lg shadow-primary-900/20"
                    )}
                  >
                    {uploading ? (
                      <>
                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        Uploading...
                      </>
                    ) : (
                      <>
                        <ShieldAlert size={20} />
                        Analyze Sample
                      </>
                    )}
                  </button>
                  <button 
                    onClick={() => setFile(null)}
                    className="px-6 py-4 bg-dark-800 text-dark-300 rounded-xl font-bold hover:bg-dark-700 transition-colors border border-dark-700"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className="p-4 bg-danger-500/10 border border-danger-500/20 rounded-xl flex items-center gap-3 text-danger-500">
              <AlertCircle size={20} />
              <p className="text-sm font-medium">{error}</p>
            </div>
          )}

          {/* Guidelines */}
          <div className="glass-card p-6">
            <h4 className="text-white font-bold mb-4 flex items-center gap-2">
              <Info size={18} className="text-primary-500" />
              Analysis Guidelines
            </h4>
            <ul className="space-y-3">
              <li className="flex gap-3 text-sm text-dark-400">
                <CheckCircle2 size={16} className="text-success-500 shrink-0 mt-0.5" />
                <span>All files are analyzed in a strictly isolated, non-persistent sandbox environment.</span>
              </li>
              <li className="flex gap-3 text-sm text-dark-400">
                <CheckCircle2 size={16} className="text-success-500 shrink-0 mt-0.5" />
                <span>Personal data is never stored; only technical indicators and behavior logs are retained.</span>
              </li>
              <li className="flex gap-3 text-sm text-dark-400">
                <CheckCircle2 size={16} className="text-success-500 shrink-0 mt-0.5" />
                <span>Analysis usually takes 2-5 minutes depending on file complexity and sandbox requirements.</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Info Sidebar */}
        <div className="space-y-6">
          <div className="glass-card p-6 border-l-4 border-primary-600">
            <h4 className="text-white font-bold mb-2">Legal Disclaimer</h4>
            <p className="text-xs text-dark-400 leading-relaxed">
              By uploading a file, you confirm that you have the right to analyze it. This tool is for authorized security research and incident response only. Misuse for offensive purposes is strictly prohibited.
            </p>
          </div>

          <div className="glass-card p-6">
            <h4 className="text-white font-bold mb-4">Supported Types</h4>
            <div className="flex flex-wrap gap-2">
              {['EXE', 'DLL', 'ELF', 'PDF', 'DOCX', 'XLSX', 'JS', 'PS1', 'VBS', 'SH', 'APK', 'ZIP'].map(type => (
                <span key={type} className="px-2 py-1 bg-dark-800 rounded text-[10px] font-bold text-dark-400 border border-dark-700">
                  {type}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-gradient-to-br from-primary-900/20 to-primary-600/10 p-6 rounded-2xl border border-primary-500/20">
            <h4 className="text-primary-400 font-bold mb-2">AI-Powered Reports</h4>
            <p className="text-xs text-dark-300 leading-relaxed mb-4">
              Our advanced AI model will automatically generate a human-readable executive summary and detailed behavior analysis for every sample.
            </p>
            <div className="flex items-center gap-2 text-[10px] font-bold text-primary-500 uppercase tracking-wider">
              <Activity size={14} />
              Powered by GPT-4
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Upload;
