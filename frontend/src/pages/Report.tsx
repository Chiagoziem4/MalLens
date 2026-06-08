import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  ChevronLeft, 
  Download, 
  Share2, 
  ShieldAlert, 
  FileText, 
  Activity, 
  Network, 
  Search,
  AlertTriangle,
  Info,
  Clock,
  Terminal,
  Database,
  Globe,
  Cpu,
  Layers,
  Fingerprint
} from 'lucide-react';
import axios from 'axios';
import { clsx } from 'clsx';
import * as Tabs from '@radix-ui/react-tabs';

const Report = () => {
  const { id } = useParams();
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const response = await axios.get(`/api/report/${id}`);
        setReport(response.data);
      } catch (err) {
        console.error('Failed to fetch report', err);
        setError('Analysis report not found or still processing.');
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [id]);

  if (loading) return (
    <div className="flex-1 flex items-center justify-center bg-dark-950">
      <div className="flex flex-col items-center gap-4">
        <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-dark-400 font-medium">Loading analysis results...</p>
      </div>
    </div>
  );

  if (error || !report) return (
    <div className="flex-1 flex items-center justify-center bg-dark-950 p-8">
      <div className="glass-card p-12 max-w-md w-full text-center">
        <AlertTriangle size={48} className="text-warning-500 mx-auto mb-6" />
        <h2 className="text-2xl font-bold text-white mb-4">Analysis Not Found</h2>
        <p className="text-dark-400 mb-8">{error}</p>
        <Link to="/queue" className="px-6 py-3 bg-primary-600 text-white rounded-xl font-bold hover:bg-primary-700 transition-colors inline-block">
          Back to Queue
        </Link>
      </div>
    </div>
  );

  const { analysis, static: staticData, dynamic, iocs, report: aiReport } = report;

  return (
    <div className="flex-1 overflow-y-auto bg-dark-950">
      {/* Top Navigation */}
      <div className="sticky top-0 z-10 glass border-b border-dark-800 px-8 py-4 flex justify-between items-center">
        <div className="flex items-center gap-4">
          <Link to="/queue" className="p-2 hover:bg-dark-800 rounded-lg text-dark-400 transition-colors">
            <ChevronLeft size={20} />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white">{analysis.file_name}</h2>
              <span className={clsx(
                "text-[10px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wide border",
                analysis.threat_level === 'critical' ? "bg-danger-600/20 text-danger-500 border-danger-600/30" :
                analysis.threat_level === 'high' ? "bg-danger-400/20 text-danger-400 border-danger-400/30" :
                analysis.threat_level === 'medium' ? "bg-warning-500/20 text-warning-500 border-warning-500/30" :
                "bg-success-500/20 text-success-500 border-success-500/30"
              )}>
                {analysis.threat_level}
              </span>
            </div>
            <p className="text-xs text-dark-500 font-mono">SHA256: {staticData.hashes.sha256.substring(0, 32)}...</p>
          </div>
        </div>
        <div className="flex gap-3">
          <button className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-dark-200 rounded-lg text-sm font-bold border border-dark-700 flex items-center gap-2 transition-colors">
            <Download size={16} />
            Export
          </button>
          <button className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm font-bold flex items-center gap-2 transition-colors">
            <Share2 size={16} />
            Share
          </button>
        </div>
      </div>

      <div className="p-8 space-y-8">
        {/* Quick Info Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="glass-card p-6 border-l-4 border-danger-600">
            <div className="flex justify-between items-start mb-4">
              <ShieldAlert className="text-danger-500" size={24} />
              <div className="text-right">
                <p className="text-[10px] font-bold text-dark-500 uppercase">Threat Score</p>
                <h4 className="text-2xl font-bold text-white">{analysis.threat_score}/100</h4>
              </div>
            </div>
            <div className="w-full h-1.5 bg-dark-800 rounded-full overflow-hidden">
              <div className="h-full bg-danger-600" style={{ width: `${analysis.threat_score}%` }}></div>
            </div>
          </div>

          <div className="glass-card p-6">
            <div className="flex justify-between items-start mb-4">
              <Activity className="text-primary-500" size={24} />
              <div className="text-right">
                <p className="text-[10px] font-bold text-dark-500 uppercase">Behavior Tags</p>
                <h4 className="text-2xl font-bold text-white">{dynamic.behavior_tags.length}</h4>
              </div>
            </div>
            <div className="flex flex-wrap gap-1">
              {dynamic.behavior_tags.slice(0, 3).map((tag: string) => (
                <span key={tag} className="text-[9px] px-1.5 py-0.5 bg-primary-500/10 text-primary-400 rounded border border-primary-500/20">{tag}</span>
              ))}
              {dynamic.behavior_tags.length > 3 && <span className="text-[9px] text-dark-500">+{dynamic.behavior_tags.length - 3} more</span>}
            </div>
          </div>

          <div className="glass-card p-6">
            <div className="flex justify-between items-start mb-4">
              <Network className="text-warning-500" size={24} />
              <div className="text-right">
                <p className="text-[10px] font-bold text-dark-500 uppercase">IOCs Found</p>
                <h4 className="text-2xl font-bold text-white">{iocs.length}</h4>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-dark-400">
              <Globe size={12} /> {dynamic.dns_queries.length} Domains | <Activity size={12} /> {dynamic.tcp_connections.length} Connections
            </div>
          </div>

          <div className="glass-card p-6">
            <div className="flex justify-between items-start mb-4">
              <Cpu className="text-success-500" size={24} />
              <div className="text-right">
                <p className="text-[10px] font-bold text-dark-500 uppercase">Sandbox Run</p>
                <h4 className="text-2xl font-bold text-white">{Math.round(dynamic.execution_duration)}s</h4>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-dark-400">
              <Clock size={12} /> {new Date(analysis.completed_at).toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Main Content Tabs */}
        <Tabs.Root defaultValue="summary" className="space-y-6">
          <Tabs.List className="flex gap-2 p-1 bg-dark-900 rounded-xl border border-dark-800 w-fit">
            <Tabs.Trigger 
              value="summary" 
              className="px-6 py-2 rounded-lg text-sm font-bold text-dark-400 data-[state=active]:bg-dark-800 data-[state=active]:text-white data-[state=active]:shadow-lg transition-all"
            >
              Executive Summary
            </Tabs.Trigger>
            <Tabs.Trigger 
              value="static" 
              className="px-6 py-2 rounded-lg text-sm font-bold text-dark-400 data-[state=active]:bg-dark-800 data-[state=active]:text-white data-[state=active]:shadow-lg transition-all"
            >
              Static Analysis
            </Tabs.Trigger>
            <Tabs.Trigger 
              value="behavior" 
              className="px-6 py-2 rounded-lg text-sm font-bold text-dark-400 data-[state=active]:bg-dark-800 data-[state=active]:text-white data-[state=active]:shadow-lg transition-all"
            >
              Behavioral
            </Tabs.Trigger>
            <Tabs.Trigger 
              value="iocs" 
              className="px-6 py-2 rounded-lg text-sm font-bold text-dark-400 data-[state=active]:bg-dark-800 data-[state=active]:text-white data-[state=active]:shadow-lg transition-all"
            >
              IOCs & Network
            </Tabs.Trigger>
          </Tabs.List>

          {/* Summary Tab */}
          <Tabs.Content value="summary" className="space-y-6 animate-in fade-in duration-300">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 space-y-6">
                <div className="glass-card p-8 relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-4 opacity-10">
                    <Activity size={120} />
                  </div>
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-primary-600/20 text-primary-500 rounded-lg">
                      <FileText size={24} />
                    </div>
                    <h3 className="text-xl font-bold text-white">Analysis Summary</h3>
                    {aiReport.generator === 'ai' && (
                      <span className="text-[10px] px-2 py-0.5 bg-primary-500/10 text-primary-500 border border-primary-500/20 rounded font-bold uppercase tracking-widest ml-auto">AI Generated</span>
                    )}
                  </div>
                  <div className="prose prose-invert max-w-none text-dark-300 leading-relaxed space-y-6">
                    <div dangerouslySetInnerHTML={{ __html: aiReport.executive_summary.replace(/\n/g, '<br/>') }} />
                    <div className="p-6 bg-dark-900/50 rounded-xl border border-dark-800">
                      <h4 className="text-white font-bold mb-4 flex items-center gap-2">
                        <ShieldAlert size={18} className="text-danger-500" />
                        Risk Assessment
                      </h4>
                      <div dangerouslySetInnerHTML={{ __html: aiReport.risk_assessment.replace(/\n/g, '<br/>') }} />
                    </div>
                  </div>
                </div>

                <div className="glass-card p-8">
                  <h3 className="text-xl font-bold text-white mb-6 flex items-center gap-3">
                    <CheckCircle2 size={24} className="text-success-500" />
                    Recommendations
                  </h3>
                  <div className="prose prose-invert max-w-none text-dark-300 leading-relaxed">
                    <div dangerouslySetInnerHTML={{ __html: aiReport.recommendations.replace(/\n/g, '<br/>') }} />
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div className="glass-card p-6">
                  <h4 className="text-white font-bold mb-4 flex items-center gap-2">
                    <Layers size={18} className="text-primary-500" />
                    MITRE ATT&CK Mapping
                  </h4>
                  <div className="space-y-3">
                    {aiReport.mitre_mapping.map((tech: any) => (
                      <div key={tech.id} className="p-3 bg-dark-900 rounded-lg border border-dark-800 hover:border-primary-500/50 transition-colors">
                        <div className="flex justify-between items-start mb-1">
                          <span className="text-[10px] font-bold text-primary-500">{tech.id}</span>
                          <span className="text-[9px] px-1.5 py-0.5 bg-dark-800 text-dark-400 rounded border border-dark-700">{tech.tactic}</span>
                        </div>
                        <p className="text-sm font-bold text-white">{tech.name}</p>
                      </div>
                    ))}
                    {aiReport.mitre_mapping.length === 0 && (
                      <p className="text-sm text-dark-500 text-center py-4 italic">No techniques identified</p>
                    )}
                  </div>
                </div>

                <div className="glass-card p-6">
                  <h4 className="text-white font-bold mb-4 flex items-center gap-2">
                    <AlertTriangle size={18} className="text-warning-500" />
                    Behavioral Signatures
                  </h4>
                  <div className="space-y-3">
                    {dynamic.signatures_matched.map((sig: any, i: number) => (
                      <div key={i} className="p-3 bg-dark-900 rounded-lg border border-dark-800">
                        <div className="flex items-center gap-2 mb-1">
                          <div className={clsx(
                            "w-2 h-2 rounded-full",
                            sig.severity === 'critical' ? "bg-danger-600" :
                            sig.severity === 'high' ? "bg-danger-400" :
                            sig.severity === 'medium' ? "bg-warning-500" : "bg-primary-500"
                          )}></div>
                          <p className="text-sm font-bold text-white">{sig.name}</p>
                        </div>
                        <p className="text-xs text-dark-400 leading-snug">{sig.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </Tabs.Content>

          {/* Static Analysis Tab */}
          <Tabs.Content value="static" className="space-y-6 animate-in fade-in duration-300">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="glass-card p-6">
                <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                  <Info size={20} className="text-primary-500" />
                  File Metadata
                </h3>
                <div className="space-y-4">
                  <MetadataItem label="Architecture" value={staticData.architecture} />
                  <MetadataItem label="File Type" value={staticData.file_type_detail} />
                  <MetadataItem label="Entropy" value={`${staticData.entropy.toFixed(4)} (${staticData.is_packed === 'True' ? 'High/Packed' : 'Normal'})`} />
                  <MetadataItem label="Packer" value={staticData.packer || 'None detected'} />
                  <div className="pt-4 border-t border-dark-800">
                    <p className="text-[10px] font-bold text-dark-500 uppercase mb-2">Hashes</p>
                    <div className="space-y-2">
                      <HashItem label="MD5" value={staticData.hashes.md5} />
                      <HashItem label="SHA1" value={staticData.hashes.sha1} />
                      <HashItem label="SHA256" value={staticData.hashes.sha256} />
                    </div>
                  </div>
                </div>
              </div>

              <div className="glass-card p-6">
                <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                  <Terminal size={20} className="text-primary-500" />
                  Suspicious Imports
                </h3>
                <div className="flex flex-wrap gap-2">
                  {staticData.suspicious_imports.map((imp: string) => (
                    <span key={imp} className="px-3 py-1.5 bg-danger-500/10 text-danger-400 border border-danger-500/20 rounded-lg text-xs font-mono font-bold">
                      {imp}
                    </span>
                  ))}
                  {staticData.suspicious_imports.length === 0 && (
                    <p className="text-sm text-dark-500 italic">No suspicious imports identified</p>
                  )}
                </div>
                
                <h3 className="text-lg font-bold text-white mt-8 mb-6 flex items-center gap-2">
                  <Fingerprint size={20} className="text-primary-500" />
                  YARA Matches
                </h3>
                <div className="space-y-3">
                  {staticData.yara_matches.map((match: any, i: number) => (
                    <div key={i} className="p-3 bg-dark-900 rounded-lg border border-dark-800">
                      <p className="text-sm font-bold text-white">{match.rule}</p>
                      <p className="text-xs text-dark-500">Namespace: {match.namespace}</p>
                    </div>
                  ))}
                  {staticData.yara_matches.length === 0 && (
                    <p className="text-sm text-dark-500 italic">No YARA rules matched</p>
                  )}
                </div>
              </div>
            </div>

            <div className="glass-card p-6">
              <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                <Search size={20} className="text-primary-500" />
                Interesting Strings
              </h3>
              <div className="max-h-96 overflow-y-auto space-y-2 pr-2">
                {staticData.interesting_strings.map((str: any, i: number) => (
                  <div key={i} className="p-2 bg-dark-900 rounded border border-dark-800 flex justify-between items-center group">
                    <span className="text-xs font-mono text-dark-300 break-all">{str.value}</span>
                    <span className="text-[9px] px-1.5 py-0.5 bg-dark-800 text-dark-500 rounded border border-dark-700 shrink-0 ml-4 group-hover:text-primary-400 group-hover:border-primary-500/30 transition-colors">
                      {str.category}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </Tabs.Content>

          {/* Behavioral Tab */}
          <Tabs.Content value="behavior" className="space-y-6 animate-in fade-in duration-300">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Timeline */}
              <div className="lg:col-span-2 glass-card p-6">
                <h3 className="text-lg font-bold text-white mb-8 flex items-center gap-2">
                  <Clock size={20} className="text-primary-500" />
                  Behavioral Timeline
                </h3>
                <div className="relative space-y-8 before:absolute before:inset-0 before:ml-4 before:-translate-x-px before:h-full before:w-0.5 before:bg-gradient-to-b before:from-primary-500 before:via-dark-800 before:to-transparent">
                  {dynamic.behavior_timeline.map((event: any, i: number) => (
                    <div key={i} className="relative flex items-start gap-6 group">
                      <div className="absolute left-0 w-8 h-8 rounded-full bg-dark-950 border-2 border-primary-600 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                        <div className="w-2 h-2 rounded-full bg-primary-500"></div>
                      </div>
                      <div className="ml-8 pt-1">
                        <span className="text-[10px] font-bold text-primary-500 uppercase tracking-widest">{event.timestamp}</span>
                        <h4 className="text-white font-bold mt-1">{event.event}</h4>
                        <p className="text-sm text-dark-400 mt-1 leading-relaxed">{event.detail}</p>
                        <span className="inline-block mt-2 text-[9px] px-1.5 py-0.5 bg-dark-900 text-dark-500 rounded border border-dark-800 uppercase tracking-tighter">
                          {event.category}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Process Tree */}
              <div className="glass-card p-6">
                <h3 className="text-lg font-bold text-white mb-8 flex items-center gap-2">
                  <Activity size={20} className="text-primary-500" />
                  Process Tree
                </h3>
                <div className="space-y-4">
                  {dynamic.process_tree.map((node: any, i: number) => (
                    <ProcessNode key={i} node={node} level={0} />
                  ))}
                </div>

                <h3 className="text-lg font-bold text-white mt-12 mb-6 flex items-center gap-2">
                  <Database size={20} className="text-primary-500" />
                  System Modifications
                </h3>
                <div className="space-y-6">
                  <div>
                    <p className="text-[10px] font-bold text-dark-500 uppercase mb-3 tracking-wider">Files Created ({dynamic.files_created.length})</p>
                    <div className="space-y-2">
                      {dynamic.files_created.slice(0, 5).map((f: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-dark-400 bg-dark-900 p-2 rounded border border-dark-800 break-all">
                          {f.path}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-dark-500 uppercase mb-3 tracking-wider">Registry Keys ({dynamic.registry_keys_created.length})</p>
                    <div className="space-y-2">
                      {dynamic.registry_keys_created.slice(0, 5).map((r: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-dark-400 bg-dark-900 p-2 rounded border border-dark-800 break-all">
                          {r.key}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Tabs.Content>

          {/* IOCs Tab */}
          <Tabs.Content value="iocs" className="space-y-6 animate-in fade-in duration-300">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="glass-card p-6">
                <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                  <ShieldAlert size={20} className="text-primary-500" />
                  Indicators of Compromise
                </h3>
                <div className="space-y-3">
                  {iocs.map((ioc: any) => (
                    <div key={ioc.id} className="p-4 bg-dark-900 rounded-xl border border-dark-800 hover:border-dark-700 transition-all group">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold text-primary-500 uppercase px-1.5 py-0.5 bg-primary-500/10 rounded border border-primary-500/20">{ioc.type}</span>
                          <span className={clsx(
                            "text-[10px] font-bold uppercase",
                            ioc.severity === 'critical' ? "text-danger-600" :
                            ioc.severity === 'high' ? "text-danger-400" :
                            ioc.severity === 'medium' ? "text-warning-500" : "text-primary-500"
                          )}>
                            {ioc.severity}
                          </span>
                        </div>
                        <span className="text-[9px] text-dark-500">{ioc.source}</span>
                      </div>
                      <p className="text-sm font-mono text-white break-all mb-2">{ioc.value}</p>
                      <p className="text-xs text-dark-500">{ioc.context}</p>
                    </div>
                  ))}
                  {iocs.length === 0 && (
                    <p className="text-sm text-dark-500 text-center py-12 italic">No IOCs extracted</p>
                  )}
                </div>
              </div>

              <div className="space-y-6">
                <div className="glass-card p-6">
                  <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                    <Globe size={20} className="text-primary-500" />
                    Network Activity
                  </h3>
                  <div className="space-y-6">
                    <div>
                      <p className="text-[10px] font-bold text-dark-500 uppercase mb-3 tracking-wider">DNS Queries ({dynamic.dns_queries.length})</p>
                      <div className="space-y-2">
                        {dynamic.dns_queries.map((dns: any, i: number) => (
                          <div key={i} className="flex justify-between items-center p-2 bg-dark-900 rounded border border-dark-800">
                            <span className="text-xs font-bold text-white">{dns.domain}</span>
                            <span className="text-[10px] font-mono text-dark-500">{dns.resolved_ip}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-dark-500 uppercase mb-3 tracking-wider">HTTP Requests ({dynamic.http_requests.length})</p>
                      <div className="space-y-2">
                        {dynamic.http_requests.map((http: any, i: number) => (
                          <div key={i} className="p-2 bg-dark-900 rounded border border-dark-800">
                            <div className="flex justify-between items-center mb-1">
                              <span className="text-[10px] font-bold text-primary-500 uppercase">{http.method}</span>
                              <span className="text-[10px] text-success-500 font-bold">{http.status}</span>
                            </div>
                            <p className="text-[10px] font-mono text-dark-400 break-all">{http.url}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </Tabs.Content>
        </Tabs.Root>
      </div>
    </div>
  );
};

const MetadataItem = ({ label, value }: any) => (
  <div className="flex justify-between items-center py-2 border-b border-dark-800/50">
    <span className="text-xs text-dark-500">{label}</span>
    <span className="text-sm font-bold text-white">{value}</span>
  </div>
);

const HashItem = ({ label, value }: any) => (
  <div className="space-y-1">
    <p className="text-[9px] font-bold text-dark-600">{label}</p>
    <div className="p-2 bg-dark-900 rounded border border-dark-800 flex justify-between items-center group">
      <code className="text-[10px] text-dark-300 break-all">{value}</code>
      <button 
        onClick={() => navigator.clipboard.writeText(value)}
        className="text-[9px] text-primary-500 font-bold opacity-0 group-hover:opacity-100 transition-opacity ml-4 shrink-0"
      >
        COPY
      </button>
    </div>
  </div>
);

const ProcessNode = ({ node, level }: any) => (
  <div className="space-y-2">
    <div className={clsx(
      "p-3 rounded-lg border flex items-center gap-3 group transition-all",
      level === 0 ? "bg-primary-500/10 border-primary-500/30" : "bg-dark-900 border-dark-800 ml-6 relative before:absolute before:-left-3 before:top-1/2 before:w-3 before:h-px before:bg-dark-700"
    )}>
      <div className={clsx(
        "w-8 h-8 rounded flex items-center justify-center shrink-0",
        level === 0 ? "bg-primary-600 text-white" : "bg-dark-800 text-dark-400"
      )}>
        <Terminal size={14} />
      </div>
      <div className="overflow-hidden">
        <p className="text-sm font-bold text-white truncate">{node.name}</p>
        <p className="text-[10px] text-dark-500 font-mono">PID: {node.pid}</p>
      </div>
    </div>
    {node.children && node.children.map((child: any, i: number) => (
      <ProcessNode key={i} node={child} level={level + 1} />
    ))}
  </div>
);

export default Report;
