import { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  ShieldCheck, 
  ShieldAlert, 
  FileWarning, 
  Clock, 
  ArrowUpRight,
  ExternalLink,
  Activity
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area,
  Cell,
  PieChart,
  Pie
} from 'recharts';
import { Link } from 'react-router-dom';
import axios from 'axios';

const Dashboard = () => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get('/api/dashboard');
        setStats(response.data);
      } catch (error) {
        console.error('Failed to fetch stats', error);
        // Mock data for demo
        setStats({
          total_analyses: 1248,
          status_breakdown: { completed: 1180, processing: 45, error: 23 },
          threat_breakdown: { critical: 156, high: 284, medium: 412, low: 320, clean: 76 },
          top_ioc_types: [
            { type: 'IP', count: 452 },
            { type: 'Domain', count: 321 },
            { type: 'URL', count: 189 },
            { type: 'Hash', count: 124 },
            { type: 'Mutex', count: 45 }
          ],
          recent_analyses: [
            { id: '1', file_name: 'invoice_7721.exe', status: 'completed', threat_level: 'critical', threat_score: 92, created_at: '2026-05-30T14:20:00' },
            { id: '2', file_name: 'chrome_update.bin', status: 'completed', threat_level: 'high', threat_score: 78, created_at: '2026-05-30T13:45:00' },
            { id: '3', file_name: 'document.pdf', status: 'completed', threat_level: 'clean', threat_score: 5, created_at: '2026-05-30T12:10:00' },
            { id: '4', file_name: 'setup_vlc.exe', status: 'processing', threat_level: 'unknown', threat_score: 0, created_at: '2026-05-30T11:55:00' },
            { id: '5', file_name: 'macro_test.docm', status: 'completed', threat_level: 'medium', threat_score: 45, created_at: '2026-05-30T10:30:00' },
          ]
        });
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  const threatChartData = stats ? [
    { name: 'Critical', value: stats.threat_breakdown.critical, color: '#ef4444' },
    { name: 'High', value: stats.threat_breakdown.high, color: '#f97316' },
    { name: 'Medium', value: stats.threat_breakdown.medium, color: '#eab308' },
    { name: 'Low', value: stats.threat_breakdown.low, color: '#3b82f6' },
    { name: 'Clean', value: stats.threat_breakdown.clean, color: '#22c55e' },
  ] : [];

  const activityData = [
    { time: '00:00', count: 12 }, { time: '04:00', count: 8 },
    { time: '08:00', count: 45 }, { time: '12:00', count: 82 },
    { time: '16:00', count: 65 }, { time: '20:00', count: 34 },
    { time: '23:59', count: 18 },
  ];

  if (loading) return (
    <div className="flex-1 flex items-center justify-center bg-dark-950">
      <div className="flex flex-col items-center gap-4">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-dark-400 font-medium">Initializing Dashboard...</p>
      </div>
    </div>
  );

  return (
    <div className="flex-1 overflow-y-auto p-8 space-y-8 bg-dark-950">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-3xl font-bold text-white mb-1">Security Overview</h2>
          <p className="text-dark-400">Welcome back, gozar. Here's what's happening with MalLens.</p>
        </div>
        <div className="flex gap-3">
          <div className="px-4 py-2 bg-dark-900 border border-dark-800 rounded-lg flex items-center gap-2">
            <Clock size={16} className="text-dark-500" />
            <span className="text-sm text-dark-300">Last 24 Hours</span>
          </div>
          <Link to="/upload" className="px-6 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-semibold transition-colors flex items-center gap-2">
            <Upload size={18} />
            New Analysis
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          title="Total Analyses" 
          value={stats.total_analyses} 
          trend="+12%" 
          icon={Activity} 
          color="blue" 
        />
        <StatCard 
          title="Critical Threats" 
          value={stats.threat_breakdown.critical} 
          trend="+5%" 
          icon={ShieldAlert} 
          color="red" 
        />
        <StatCard 
          title="Avg. Threat Score" 
          value="64.2" 
          trend="-2.4" 
          icon={TrendingUp} 
          color="orange" 
        />
        <StatCard 
          title="System Health" 
          value="Optimal" 
          trend="100%" 
          icon={ShieldCheck} 
          color="green" 
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Activity Chart */}
        <div className="lg:col-span-2 glass-card p-6">
          <div className="flex justify-between items-center mb-8">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <TrendingUp size={20} className="text-primary-500" />
              Analysis Activity
            </h3>
            <button className="text-xs text-primary-500 hover:underline">View Detailed Logs</button>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                  itemStyle={{ color: '#3b82f6' }}
                />
                <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorCount)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-8 flex items-center gap-2">
            <FileWarning size={20} className="text-danger-500" />
            Threat Distribution
          </h3>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={threatChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {threatChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-4 mt-4">
            {threatChartData.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }}></div>
                <span className="text-xs text-dark-400">{item.name}: </span>
                <span className="text-xs font-bold text-white">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Analyses Table */}
      <div className="glass-card overflow-hidden">
        <div className="p-6 border-b border-dark-800 flex justify-between items-center">
          <h3 className="text-lg font-bold text-white">Recent Analyses</h3>
          <Link to="/queue" className="text-sm text-primary-500 hover:text-primary-400 flex items-center gap-1">
            View All <ArrowUpRight size={14} />
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-dark-900/50 text-left">
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">File Name</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Threat Level</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Score</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider">Date</th>
                <th className="px-6 py-4 text-xs font-semibold text-dark-500 uppercase tracking-wider text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {stats.recent_analyses.map((analysis: any) => (
                <tr key={analysis.id} className="hover:bg-dark-800/30 transition-colors group">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded bg-dark-800 flex items-center justify-center text-dark-400 group-hover:text-primary-400 transition-colors">
                        <FileText size={16} />
                      </div>
                      <span className="text-sm font-medium text-dark-200">{analysis.file_name}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={clsx(
                      "text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wide border",
                      analysis.status === 'completed' ? "bg-success-500/10 text-success-500 border-success-500/20" : 
                      analysis.status === 'processing' ? "bg-primary-500/10 text-primary-500 border-primary-500/20 animate-pulse" :
                      "bg-danger-500/10 text-danger-500 border-danger-500/20"
                    )}>
                      {analysis.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className={clsx(
                        "w-2 h-2 rounded-full",
                        analysis.threat_level === 'critical' ? "bg-danger-600" :
                        analysis.threat_level === 'high' ? "bg-danger-400" :
                        analysis.threat_level === 'medium' ? "bg-warning-500" :
                        analysis.threat_level === 'low' ? "bg-primary-500" : "bg-success-500"
                      )}></div>
                      <span className="text-sm capitalize text-dark-300">{analysis.threat_level}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 bg-dark-800 rounded-full overflow-hidden">
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
                      <span className="text-xs font-mono text-dark-400">{analysis.threat_score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-dark-500">
                    {new Date(analysis.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <Link 
                      to={`/report/${analysis.id}`} 
                      className="inline-flex items-center gap-1 text-xs font-bold text-primary-500 hover:text-primary-400"
                    >
                      VIEW REPORT <ExternalLink size={12} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const StatCard = ({ title, value, trend, icon: Icon, color }: any) => {
  const colorMap: any = {
    blue: "text-primary-500 bg-primary-500/10 border-primary-500/20",
    red: "text-danger-500 bg-danger-500/10 border-danger-500/20",
    orange: "text-warning-500 bg-warning-500/10 border-warning-500/20",
    green: "text-success-500 bg-success-500/10 border-success-500/20",
  };

  const isPositive = trend.startsWith('+');

  return (
    <div className="glass-card p-6 flex flex-col gap-4">
      <div className="flex justify-between items-start">
        <div className={clsx("p-3 rounded-xl border", colorMap[color])}>
          <Icon size={24} />
        </div>
        <div className={clsx(
          "flex items-center gap-1 text-xs font-bold px-2 py-1 rounded-full",
          isPositive ? "text-success-500 bg-success-500/10" : "text-danger-500 bg-danger-500/10"
        )}>
          {trend}
        </div>
      </div>
      <div>
        <p className="text-sm font-medium text-dark-500 mb-1">{title}</p>
        <h4 className="text-2xl font-bold text-white">{value}</h4>
      </div>
    </div>
  );
};

export default Dashboard;
