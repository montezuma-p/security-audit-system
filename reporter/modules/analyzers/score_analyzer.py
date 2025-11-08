#!/usr/bin/env python3
"""
Score Analyzer - Analisa o score de segurança do sistema
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class ScoreAnalyzer(BaseAnalyzer):
    """Analisa o score de segurança e gera insights"""
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analisa o score de segurança
        
        Returns:
            Insights sobre o score
        """
        score = self.security_score.get('score', 0)
        grade = self.security_score.get('grade', 'N/A')
        deductions = self.security_score.get('deductions', [])
        bonus = self.security_score.get('bonus', [])
        
        # Determinar status baseado no score
        if score >= 90:
            status = 'good'
            status_text = '✅ EXCELENTE'
            severity = 'low'
        elif score >= 70:
            status = 'warning'
            status_text = '⚠️ BOM - Melhorias Recomendadas'
            severity = 'medium'
        elif score >= 50:
            status = 'warning'
            status_text = '⚠️ REGULAR - Ação Necessária'
            severity = 'high'
        else:
            status = 'critical'
            status_text = '🚨 CRÍTICO - Ação Imediata Necessária'
            severity = 'critical'
        
        # Gerar mensagem didática
        message = self._generate_message(score, grade, deductions, bonus)
        
        # Detalhes
        details = []
        if deductions:
            details.append(f"Deduções aplicadas: {len(deductions)}")
        if bonus:
            details.append(f"Bônus aplicados: {len(bonus)}")
        
        # Recomendações baseadas no score
        recommendations = self._generate_recommendations(score, deductions)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'score': score,
                'grade': grade,
                'deductions_count': len(deductions),
                'bonus_count': len(bonus),
                'total_alerts': self.summary.get('total_alerts', 0),
                'critical_alerts': self.summary.get('critical_alerts', 0)
            }
        }
    
    def _generate_message(self, score: int, grade: str, deductions: list, bonus: list) -> str:
        """Gera mensagem explicativa sobre o score"""
        
        if score >= 90:
            msg = f"A pontuação de {score}/100 (Grau {grade}) indica uma **excelente postura de segurança**. "
            msg += "O sistema está bem configurado com os pilares fundamentais de segurança implementados corretamente. "
            
            if bonus:
                msg += f"Foram aplicados {len(bonus)} bônus por boas práticas de segurança. "
            
            if deductions:
                msg += f"No entanto, existem {len(deductions)} pontos de melhoria identificados que, se corrigidos, "
                msg += "podem elevar ainda mais a segurança. "
            else:
                msg += "Nenhuma dedução foi aplicada, indicando conformidade total com as verificações realizadas. "
            
            msg += "Continue monitorando e mantendo o sistema atualizado para preservar este nível de segurança."
        
        elif score >= 70:
            msg = f"A pontuação de {score}/100 (Grau {grade}) indica uma **boa postura de segurança**, "
            msg += "mas com espaço para melhorias importantes. "
            
            if deductions:
                msg += f"Foram aplicadas {len(deductions)} deduções, indicando áreas que necessitam atenção. "
                msg += "As principais vulnerabilidades identificadas podem comprometer a segurança se não forem tratadas. "
            
            msg += "Recomenda-se priorizar as correções sugeridas para alcançar um nível de segurança excelente."
        
        elif score >= 50:
            msg = f"A pontuação de {score}/100 (Grau {grade}) indica uma postura de segurança **regular** "
            msg += "com **vulnerabilidades significativas** que requerem ação imediata. "
            
            if deductions:
                msg += f"Foram identificados {len(deductions)} problemas de segurança que estão reduzindo o score. "
            
            msg += "O sistema apresenta riscos que podem ser explorados por atacantes. "
            msg += "É **fortemente recomendado** implementar as correções sugeridas o mais rápido possível."
        
        else:
            msg = f"A pontuação de {score}/100 (Grau {grade}) indica uma postura de segurança **CRÍTICA**. "
            msg += f"O sistema apresenta {len(deductions)} problemas graves que o deixam extremamente vulnerável a ataques. "
            msg += "**AÇÃO IMEDIATA É NECESSÁRIA** para corrigir as falhas de segurança identificadas. "
            msg += "O sistema está em alto risco e pode ser comprometido facilmente por atacantes."
        
        return msg
    
    def _generate_recommendations(self, score: int, deductions: list) -> list:
        """Gera recomendações baseadas no score"""
        
        recommendations = []
        
        if score < 90:
            recommendations.append({
                'title': 'Revisar e Corrigir Deduções',
                'description': 'Analise cada dedução aplicada e implemente as correções sugeridas em cada seção deste relatório.',
                'priority': 'high' if score < 70 else 'medium'
            })
        
        if score < 70:
            recommendations.append({
                'title': 'Implementar Monitoramento Contínuo',
                'description': 'Configure alertas automáticos para detectar mudanças na postura de segurança.',
                'priority': 'high'
            })
        
        if score < 50:
            recommendations.append({
                'title': 'Auditoria de Segurança Completa',
                'description': 'Considere realizar uma auditoria de segurança profissional completa do sistema.',
                'priority': 'critical'
            })
        
        return recommendations
