import { useState } from 'react'
import { useGenerateReport, type ComplianceReport } from '../api/hooks'

export default function Reports() {
  const [reportType, setReportType] = useState('soc2')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [report, setReport] = useState<ComplianceReport | null>(null)

  const mutation = useGenerateReport()

  const handleGenerate = () => {
    if (!startDate || !endDate) return
    mutation.mutate(
      { report_type: reportType, start_date: startDate, end_date: endDate },
      { onSuccess: (data) => setReport(data) },
    )
  }

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 mb-6">Compliance Reports</h2>

      {/* Form */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Report Type</label>
            <select
              value={reportType}
              onChange={e => setReportType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            >
              <option value="soc2">SOC 2</option>
              <option value="iso27001">ISO 27001</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={e => setStartDate(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={e => setEndDate(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            />
          </div>
          <button
            onClick={handleGenerate}
            disabled={mutation.isPending || !startDate || !endDate}
            className="px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            {mutation.isPending ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
        {mutation.isError && (
          <p className="mt-3 text-sm text-red-600">{mutation.error.message}</p>
        )}
      </div>

      {/* Report Output */}
      {report && (
        <div className="space-y-6">
          {/* Summary */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">
              {report.report_type === 'soc2' ? 'SOC 2' : 'ISO 27001'} Report Summary
            </h3>
            <p className="text-sm text-gray-500 mb-4">
              Period: {report.period.start} to {report.period.end}
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Stat label="Total Decisions" value={report.summary.total_decisions} />
              <Stat label="Allowed" value={report.summary.allowed} />
              <Stat label="Denied" value={report.summary.denied} />
              <Stat label="Approvals Required" value={report.summary.approvals_required} />
              <Stat label="Unique Agents" value={report.summary.unique_agents} />
              <Stat label="Unique Targets" value={report.summary.unique_targets} />
              <Stat label="High Risk Actions" value={report.summary.high_risk_actions} />
              <Stat
                label="Audit Chain"
                value={report.summary.audit_chain_valid ? 'VALID' : 'BROKEN'}
                className={report.summary.audit_chain_valid ? 'text-green-600' : 'text-red-600'}
              />
            </div>
          </div>

          {/* Sections */}
          {report.sections.map((section, i) => (
            <div key={i} className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-1">{section.title}</h3>
              <p className="text-sm text-gray-500 mb-4">{section.description}</p>
              {section.items.length === 0 ? (
                <p className="text-sm text-gray-400 italic">No data for this period.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        {Object.keys(section.items[0]).map(key => (
                          <th key={key} className="text-left py-2 px-3 font-medium text-gray-700">
                            {key}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {section.items.map((item, j) => (
                        <tr key={j} className="border-b last:border-0">
                          {Object.values(item).map((val, k) => (
                            <td key={k} className="py-2 px-3 text-gray-600">
                              {String(val)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Stat({ label, value, className = '' }: { label: string; value: string | number; className?: string }) {
  return (
    <div className="text-center">
      <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
      <p className={`text-2xl font-bold ${className || 'text-gray-900'}`}>{value}</p>
    </div>
  )
}
