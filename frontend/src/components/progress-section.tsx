'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { BarChart3, TrendingUp, BookOpen, Target, Calendar, ChevronLeft, ChevronRight } from 'lucide-react'
import { useUserStats } from '@/hooks/use-user-progress'
import { userProgressAPI } from '@/lib/api'
import { useQuery } from '@tanstack/react-query'

interface ProgressSectionProps {
  sessionId: string
  selectedDate?: string
  onDateChange?: (date: string) => void
}

interface PeriodData {
  date: string
  ai_info: number
  terms: number
  quiz_score: number
  quiz_correct: number
  quiz_total: number
}

interface PeriodStats {
  period_data: PeriodData[]
  start_date: string
  end_date: string
  total_days: number
}

function ProgressSection({ sessionId, selectedDate, onDateChange }: ProgressSectionProps) {
  // 외부에서 전달받은 selectedDate를 직접 사용
  const [periodType, setPeriodType] = useState<'week' | 'month' | 'custom'>('week')
  const [customStartDate, setCustomStartDate] = useState('')
  const [customEndDate, setCustomEndDate] = useState('')

  const { data: stats } = useUserStats(sessionId)

  // 기간별 데이터 계산
  const getPeriodDates = () => {
    const today = new Date()
    const startDate = new Date()
    
    switch (periodType) {
      case 'week':
        startDate.setDate(today.getDate() - 6)
        break
      case 'month':
        startDate.setDate(today.getDate() - 29)
        break
      case 'custom':
        if (customStartDate && customEndDate) {
          return { start: customStartDate, end: customEndDate }
        }
        startDate.setDate(today.getDate() - 6)
        break
    }
    
    return {
      start: startDate.toISOString().split('T')[0],
      end: today.toISOString().split('T')[0]
    }
  }

  const periodDates = getPeriodDates()

  const { data: periodStats } = useQuery<PeriodStats>({
    queryKey: ['period-stats', sessionId, periodDates.start, periodDates.end],
    queryFn: async () => {
      const response = await userProgressAPI.getPeriodStats(sessionId, periodDates.start, periodDates.end)
      return response.data
    },
    enabled: !!sessionId && !!periodDates.start && !!periodDates.end,
  })

  // 날짜 변경 핸들러 - 상위 컴포넌트에 알림
  const handleDateChange = (date: string) => {
    console.log('진행률 탭 - 날짜 변경:', date)
    onDateChange?.(date)
  }

  // 기간 변경 핸들러
  const handlePeriodChange = (type: 'week' | 'month' | 'custom') => {
    console.log('진행률 탭 - 기간 변경:', type)
    setPeriodType(type)
    if (type === 'custom') {
      const today = new Date()
      const weekAgo = new Date()
      weekAgo.setDate(today.getDate() - 6)
      setCustomStartDate(weekAgo.toISOString().split('T')[0])
      setCustomEndDate(today.toISOString().split('T')[0])
    }
  }

  // 커스텀 날짜 변경 핸들러
  const handleCustomStartDateChange = (date: string) => {
    console.log('진행률 탭 - 시작 날짜 변경:', date)
    setCustomStartDate(date)
  }

  const handleCustomEndDateChange = (date: string) => {
    console.log('진행률 탭 - 종료 날짜 변경:', date)
    setCustomEndDate(date)
  }

  // 그래프 데이터 준비 - 중복 제거 및 정렬
  const chartData = periodStats?.period_data || []
  
  // 날짜별로 중복 제거하고 정렬
  const uniqueChartData = chartData.reduce((acc: PeriodData[], current: PeriodData) => {
    const existingIndex = acc.findIndex(item => item.date === current.date)
    if (existingIndex === -1) {
      acc.push(current)
    } else {
      // 중복된 날짜가 있으면 더 높은 값을 사용
      acc[existingIndex] = {
        ...acc[existingIndex],
        ai_info: Math.max(acc[existingIndex].ai_info, current.ai_info),
        terms: Math.max(acc[existingIndex].terms, current.terms),
        quiz_score: Math.max(acc[existingIndex].quiz_score, current.quiz_score),
        quiz_correct: Math.max(acc[existingIndex].quiz_correct, current.quiz_correct),
        quiz_total: Math.max(acc[existingIndex].quiz_total, current.quiz_total)
      }
    }
    return acc
  }, []).sort((a: PeriodData, b: PeriodData) => new Date(a.date).getTime() - new Date(b.date).getTime())
  
  // 최대값을 고정값으로 설정 (AI 정보: 3, 용어: 60, 퀴즈: 100)
  const maxAI = 3;
  const maxTerms = 60;
  const maxQuiz = 100;

  return (
    <div className="space-y-8 relative">
      {/* 날짜 및 기간 선택 */}
      <div className="flex flex-col lg:flex-row gap-4 items-start lg:items-center justify-between relative z-10">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Calendar className="w-5 h-5 text-white/70" />
            <label htmlFor="progress-date" className="text-white/80 text-sm font-medium">
              선택 날짜:
            </label>
            <input
              id="progress-date"
              type="date"
              value={selectedDate || new Date().toISOString().split('T')[0]}
              onChange={(e) => {
                handleDateChange(e.target.value)
              }}
              className="bg-white/10 border border-white/20 rounded-lg px-4 py-3 text-white text-base focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent cursor-pointer touch-manipulation relative z-20"
              style={{ 
                colorScheme: 'dark',
                minHeight: '44px',
                WebkitAppearance: 'none',
                MozAppearance: 'none',
                position: 'relative',
                zIndex: 9999
              }}
            />
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-white/80 text-sm font-medium">기간:</span>
            <div className="flex bg-white/10 rounded-lg p-1 relative z-20">
              <button
                type="button"
                onClick={() => {
                  handlePeriodChange('week')
                }}
                onTouchStart={() => {
                  handlePeriodChange('week')
                }}
                className={`px-4 py-3 rounded-md text-sm font-medium transition-all cursor-pointer touch-manipulation min-w-[70px] min-h-[44px] relative z-30 ${
                  periodType === 'week'
                    ? 'bg-blue-500 text-white shadow-lg'
                    : 'text-white/70 hover:text-white hover:bg-white/20 active:bg-white/30'
                }`}
                style={{ 
                  WebkitTapHighlightColor: 'transparent',
                  WebkitTouchCallout: 'none',
                  WebkitUserSelect: 'none',
                  userSelect: 'none',
                  position: 'relative',
                  zIndex: 9999
                }}
              >
                주간
              </button>
              <button
                type="button"
                onClick={() => {
                  handlePeriodChange('month')
                }}
                onTouchStart={() => {
                  handlePeriodChange('month')
                }}
                className={`px-4 py-3 rounded-md text-sm font-medium transition-all cursor-pointer touch-manipulation min-w-[70px] min-h-[44px] relative z-30 ${
                  periodType === 'month'
                    ? 'bg-blue-500 text-white shadow-lg'
                    : 'text-white/70 hover:text-white hover:bg-white/20 active:bg-white/30'
                }`}
                style={{ 
                  WebkitTapHighlightColor: 'transparent',
                  WebkitTouchCallout: 'none',
                  WebkitUserSelect: 'none',
                  userSelect: 'none',
                  position: 'relative',
                  zIndex: 9999
                }}
              >
                월간
              </button>
              <button
                type="button"
                onClick={() => {
                  handlePeriodChange('custom')
                }}
                onTouchStart={() => {
                  handlePeriodChange('custom')
                }}
                className={`px-4 py-3 rounded-md text-sm font-medium transition-all cursor-pointer touch-manipulation min-w-[70px] min-h-[44px] relative z-30 ${
                  periodType === 'custom'
                    ? 'bg-blue-500 text-white shadow-lg'
                    : 'text-white/70 hover:text-white hover:bg-white/20 active:bg-white/30'
                }`}
                style={{ 
                  WebkitTapHighlightColor: 'transparent',
                  WebkitTouchCallout: 'none',
                  WebkitUserSelect: 'none',
                  userSelect: 'none',
                  position: 'relative',
                  zIndex: 9999
                }}
              >
                사용자
              </button>
            </div>
          </div>
        </div>

        {/* 사용자 정의 기간 설정 - 별도 라인에 배치 */}
        {periodType === 'custom' && (
          <div className="flex flex-col gap-3 relative z-20 bg-white/5 rounded-xl p-4 border border-white/10 mt-4">
            <div className="text-center">
              <span className="text-white/80 text-sm font-medium">사용자 정의 기간 설정</span>
            </div>
            <div className="flex flex-col gap-3">
              <div className="w-full">
                <label className="block text-white/70 text-xs font-medium mb-2">
                  📅 시작일
                </label>
                <input
                  type="date"
                  value={customStartDate}
                  onChange={(e) => {
                    handleCustomStartDateChange(e.target.value)
                  }}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer touch-manipulation relative z-30"
                  style={{ 
                    minHeight: '44px',
                    WebkitAppearance: 'none',
                    MozAppearance: 'none',
                    position: 'relative',
                    zIndex: 9999
                  }}
                />
              </div>
              <div className="flex items-center justify-center">
                <div className="w-16 h-0.5 bg-white/30 rounded-full"></div>
                <span className="text-white/50 text-xs mx-2">↓</span>
                <div className="w-16 h-0.5 bg-white/30 rounded-full"></div>
              </div>
              <div className="w-full">
                <label className="block text-white/70 text-xs font-medium mb-2">
                  📅 종료일
                </label>
                <input
                  type="date"
                  value={customEndDate}
                  onChange={(e) => {
                    handleCustomEndDateChange(e.target.value)
                  }}
                  className="w-full bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer touch-manipulation relative z-30"
                  style={{ 
                    minHeight: '44px',
                    WebkitAppearance: 'none',
                    MozAppearance: 'none',
                    position: 'relative',
                    zIndex: 9999
                  }}
                />
              </div>
            </div>
            <div className="text-center">
              <span className="text-white/50 text-xs">
                {customStartDate && customEndDate ? 
                  `${customStartDate} ~ ${customEndDate}` : 
                  '시작일과 종료일을 선택해주세요'
                }
              </span>
            </div>
          </div>
        )}
      </div>

      {/* 전체 통계 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* AI 정보 통계 */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 border border-blue-500/30 rounded-xl p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <BookOpen className="w-5 h-5 text-blue-400" />
              <h3 className="text-white font-semibold">AI 정보 학습</h3>
            </div>
            <TrendingUp className="w-4 h-4 text-blue-400" />
          </div>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">오늘 학습</span>
              <span className="text-blue-400 font-bold text-lg">
                {stats?.today_ai_info || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">총 학습</span>
              <span className="text-white font-semibold">
                {stats?.total_learned || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">총 정보 수</span>
              <span className="text-white/50 text-sm">
                {stats?.total_ai_info_available || 0}
              </span>
            </div>
          </div>
        </motion.div>

        {/* 용어 학습 통계 */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 border border-purple-500/30 rounded-xl p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Target className="w-5 h-5 text-purple-400" />
              <h3 className="text-white font-semibold">용어 학습</h3>
            </div>
            <TrendingUp className="w-4 h-4 text-purple-400" />
          </div>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">오늘 학습</span>
              <span className="text-purple-400 font-bold text-lg">
                {stats?.today_terms || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">총 학습</span>
              <span className="text-white font-semibold">
                {stats?.total_terms_learned || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">총 용어 수</span>
              <span className="text-white/50 text-sm">
                {stats?.total_terms_available || 0}
              </span>
            </div>
          </div>
        </motion.div>

        {/* 퀴즈 통계 */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="bg-gradient-to-br from-green-500/20 to-green-600/20 border border-green-500/30 rounded-xl p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <BarChart3 className="w-5 h-5 text-green-400" />
              <h3 className="text-white font-semibold">퀴즈 점수</h3>
            </div>
            <TrendingUp className="w-4 h-4 text-green-400" />
          </div>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">오늘 누적 점수</span>
              <span className="text-green-400 font-bold text-lg">
                {stats?.today_quiz_score || 0}%
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">오늘 정답률</span>
              <span className="text-white font-semibold">
                {stats?.today_quiz_correct || 0}/{stats?.today_quiz_total || 0}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-white/70 text-sm">전체 누적</span>
              <span className="text-white/50 text-sm">
                {stats?.cumulative_quiz_score || 0}%
              </span>
            </div>
          </div>
        </motion.div>
      </div>

      {/* 기간별 추이 그래프 - Progress Journey 스타일로 완전 리뉴얼 */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-white font-semibold text-lg">기간별 학습 여정</h3>
          <div className="text-white/60 text-sm">
            {periodStats?.start_date} ~ {periodStats?.end_date}
          </div>
        </div>
        <div className="glass rounded-2xl p-6 overflow-x-auto scrollbar-thin scrollbar-thumb-blue-400/30 scrollbar-track-transparent">
          {uniqueChartData.length > 0 ? (
            <div className="relative flex items-end gap-12 h-64 min-w-[600px] w-fit px-6" style={{scrollSnapType:'x mandatory'}}>
              {/* SVG 곡선 라인 */}
              <svg className="absolute left-0 top-0 w-full h-48 pointer-events-none z-0" style={{minWidth: uniqueChartData.length * 80}}>
                <polyline
                  fill="none"
                  stroke="#64748b"
                  strokeWidth="4"
                  strokeLinejoin="round"
                  points={uniqueChartData.map((_, idx) => `${40 + idx*80},180`).join(' ')}
                  style={{opacity:0.3}}
                />
              </svg>
              {uniqueChartData.map((data, idx) => {
                const isToday = data.date === new Date().toISOString().split('T')[0];
                const aiRatio = data.ai_info / maxAI;
                const termsRatio = data.terms / maxTerms;
                const quizRatio = data.quiz_score / maxQuiz;
                const totalRatio = Math.min(aiRatio + termsRatio + quizRatio, 1);
                const tooltip = `AI: ${data.ai_info}/${maxAI}\n용어: ${data.terms}/${maxTerms}\n퀴즈: ${data.quiz_score}%`;
                // 아이콘/이모지
                const aiIcon = '🤖';
                const termsIcon = '📚';
                const quizIcon = '📝';
                return (
                  <div key={idx} className="flex flex-col items-center w-20 relative z-10" style={{scrollSnapAlign: isToday ? 'center' : 'none'}}>
                    {/* 미니 bar + 아이콘 */}
                    <div className="flex flex-col gap-1 mb-2">
                      <div className="flex items-center gap-1 justify-center">
                        <span className="text-blue-400 text-lg">{aiIcon}</span>
                        <div className="w-8 h-2 rounded-full bg-gradient-to-r from-blue-500 to-cyan-300" style={{width:`${aiRatio*32}px`,opacity:aiRatio>0?1:0.2}}></div>
                        <span className="text-xs text-blue-200 font-bold ml-1">{data.ai_info}</span>
                      </div>
                      <div className="flex items-center gap-1 justify-center">
                        <span className="text-purple-400 text-lg">{termsIcon}</span>
                        <div className="w-8 h-2 rounded-full bg-gradient-to-r from-purple-500 to-pink-300" style={{width:`${termsRatio*32}px`,opacity:termsRatio>0?1:0.2}}></div>
                        <span className="text-xs text-pink-200 font-bold ml-1">{data.terms}</span>
                      </div>
                      <div className="flex items-center gap-1 justify-center">
                        <span className="text-green-400 text-lg">{quizIcon}</span>
                        <div className="w-8 h-2 rounded-full bg-gradient-to-r from-green-500 to-emerald-300" style={{width:`${quizRatio*32}px`,opacity:quizRatio>0?1:0.2}}></div>
                        <span className="text-xs text-emerald-200 font-bold ml-1">{data.quiz_score}%</span>
                      </div>
                    </div>
                    {/* 원(circle) 노드 */}
                    <div className="relative flex flex-col items-center">
                      <motion.div
                        initial={{ scale: 0.7, boxShadow: '0 0 0 0 rgba(0,0,0,0)' }}
                        animate={{ scale: isToday ? 1.2 : 1, boxShadow: isToday ? '0 0 24px 8px #fde047' : '0 2px 8px 0 #64748b55' }}
                        transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                        className={`w-12 h-12 rounded-full border-4 flex items-center justify-center font-extrabold text-lg bg-gradient-to-br from-slate-800 to-slate-700 border-white/30 ${isToday ? 'ring-4 ring-yellow-300 animate-pulse' : ''} shadow-xl cursor-pointer`}
                        tabIndex={0}
                        title={tooltip}
                      >
                        {isToday ? '🔥' : '⭐'}
                      </motion.div>
                      {/* 툴팁 */}
                      <div className="absolute left-1/2 -translate-x-1/2 -top-20 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 pointer-events-none transition-opacity z-20 w-40 bg-black/90 text-white text-xs rounded-lg px-3 py-2 shadow-xl whitespace-pre text-center">
                        {tooltip}
                      </div>
                      {/* bar 위에 총합/비율 */}
                      <div className="absolute -top-8 left-1/2 -translate-x-1/2 text-sm font-bold text-white drop-shadow-lg">
                        {Math.round(totalRatio * 100)}%
                      </div>
                    </div>
                    {/* 날짜 */}
                    <div className={`mt-3 text-xs font-bold ${isToday ? 'text-yellow-400' : 'text-white/80'} drop-shadow`}>{new Date(data.date).getDate()}</div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center text-white/60 py-8">
              <BarChart3 className="w-12 h-12 mx-auto mb-4 opacity-40" />
              <p>선택한 기간에 학습 데이터가 없습니다.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ProgressSection 
