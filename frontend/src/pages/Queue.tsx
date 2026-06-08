import { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  RefreshCw, 
  Trash2, 
  ExternalLink,
  FileText,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Loader2
} from 'lucide-react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { clsx } from 'clsx';

const Queue = () => {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchQueue = async () => {
    try {
      const response = await axios.get('/api/queue');
      setAnalyses(response.data.analyses);
    } catch (error) {
      console.error('Failed to fetch queue', error);
      // Mock data for demo if API fails
      setAnalyses([
        { id: '1', file_name: 'invoice_7721.exe', status: 'completed', threat_level: 'critical', threat_score: 92, created_at: '2026-05-30T14:20:00' },
        { id: '2', file_name: 'chrome_update.bin', status: 'completed', threat_level: 'high', threat_score: 78, created_at: '2026-05-30T13:45:00' },
        { id: '3', file_name: 'document.pdf', status: 'completed', threat_level: 'clean', threat_score: 5, created_at: '2026-05-30T12:10:00' },
        { id: '4', file_name: 'setup_vlc.exe', status: 'processing', threat_level: 'unknown', threat_score: 0, created_at: '2026-05-30T11:55:00' },
        { id: '5', file_name: 'macro_test.docm', status: 'completed', threat_level: 'medium', threat_score: 45, created_at: '2026-05-30T10:30:00' },
        { id: '6', file_name: 'suspicious.ps1', status: 'pending', threat_level: 'unknown', threat_score: 0, created_at: '2026-05-30T09:15:00' },
        { id: '7', file_name: 'payload.elf', status: 'error', threat_level: 'unknown', threat_score: 0, created_at: '2026-05-30T08:45:00' },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueue();
    // Poll for updates
    const interval = setInterval(fetchQueue, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this analysis?')) return;
    try {
      await axios.delete(`/api/analysis/${id}`);
      setAnalyses(analyses.filter(a => a.id !== id));
    } catch (error) {
      console.error('Delete failed', error);
    }
  };

  const filteredAnalyses = analyses.filter(a => 
    a.file_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex-1 p-8 overflow-y-auto space-y-8 bg-dark-950">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Analysis Queue</h2>
          <p className="text-dark-400">Manage and monitor your submitted samples.</p>
        </div>
        <div className="flex gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" size={18} />
            <input 
              type="text" 
              placeholder="Search samples..."
              className="pl-10 pr-4 py-2 bg-dark-900 border border-dark-800 rounded-lg text-sm text-dark-200 focus:outline-none focus:border-primary-500 w-64"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <button 
            onClick={() => { setLoading(true); fetchQueue(); }}
            className="p-2 bg-dark-900 border border-dark-800 rounded-lg text-dark-400 hover:text-white transition-colors"
          >
            <RefreshCw size={20} className={loading ? "animate-spin" : ""} />
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-dark-900 border border-dark-800 rounded-lg text-sm text-dark-300 hover:text-white transition-colors">
            <Filter size={18} />
            Filter
          </button>
        </div>
      </div>

      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-dark-900/50 text-left">
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Sample</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Threat Level</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Score</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Submitted</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {filteredAnalyses.length > 0 ? filteredAnalyses.map((analysis) => (
                <tr key={analysis.id} className="hover:bg-dark-800/30 transition-colors group">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-dark-800 flex items-center justify-center text-dark-400 group-hover:text-primary-400 transition-colors border border-dark-700">
                        <FileText size={20} />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-dark-100">{analysis.file_name}</p>
                        <p className="text-[10px] font-mono text-dark-500 uppercase tracking-tighter">ID: {analysis.id.substring(0, 8)}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      {analysis.status === 'completed' && <CheckCircle2 size={16} className="text-success-500" />}
                      {analysis.status === 'processing' && <Loader2 size={16} className="text-primary-500 animate-spin" />}
                      {analysis.status === 'pending' && <Clock size={16} className="text-dark-500" />}
                      {analysis.status === 'error' && <AlertTriangle size={16} className="text-danger-500" />}
                      <span className={clsx(
                        "text-xs font-medium capitalize",
                        analysis.status === 'completed' ? "text-success-500" : 
                        analysis.status === 'processing' ? "text-primary-500" :
                        analysis.status === 'error' ? "text-danger-500" : "text-dark-400"
                      )}>
                        {analysis.status}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    {analysis.status === 'completed' ? (
                      <div className="flex items-center gap-2">
                        <div className={clsx(
                          "w-2 h-2 rounded-full",
                          analysis.threat_level === 'critical' ? "bg-danger-600" :
                          analysis.threat_level === 'high' ? "bg-danger-400" :
                          analysis.threat_level === 'medium' ? "bg-warning-500" :
                          analysis.threat_level === 'low' ? "bg-primary-500" : "bg-success-500"
                        )}></div>
                        <span className="text-xs font-bold capitalize text-dark-200">{analysis.threat_level}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-dark-500">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {analysis.status === 'completed' ? (
                      <div className="flex items-center gap-3">
                        <div className="w-16 h-2 bg-dark-800 rounded-full overflow-hidden">
                          <div 
                            className={clsx(
                              "h-full",
                              analysis.threat_score > 80 ? "bg-danger-600" :
                              analysis.threat_score > 60 ? "bg-danger-400" :
                              analysis.threat_score > 30 ? "bg-warning-500" : "bg-success-500"
                            )} 
                            style={{ width: `${analysis.threat_score}%` }}
                          ></div>
                        </div>
                        <span className="text-xs font-mono font-bold text-dark-300">{analysis.threat_score}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-dark-500">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-col">
                      <span className="text-xs text-dark-300">{new Date(analysis.created_at).toLocaleDateString()}</span>
                      <span className="text-[10px] text-dark-500">{new Date(analysis.created_at).toLocaleTimeString()}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-end gap-2">
                      {analysis.status === 'completed' && (
                        <Link 
                          to={`/report/${analysis.id}`}
                          className="p-2 bg-primary-600/10 text-primary-500 hover:bg-primary-600 hover:text-white rounded-lg transition-all"
                          title="View Report"
                        >
                          <ExternalLink size={16} />
                        </Link>
                      )}
                      <button 
                        onClick={() => handleDelete(analysis.id)}
                        className="p-2 bg-danger-500/10 text-danger-500 hover:bg-danger-500 hover:text-white rounded-lg transition-all"
                        title="Delete Analysis"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center">
                    <div className="flex flex-col items-center gap-4 text-dark-500">
                      <FileText size={48} opacity={0.2} />
                      <p>No analyses found matching your search.</p>
                      <Link to="/upload" className="text-primary-500 font-bold hover:underline">Upload a new sample</Link>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Queue;
