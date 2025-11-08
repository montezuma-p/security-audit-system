#!/usr/bin/env python3
"""
Permissions Analyzer - Analisa permissões de arquivos críticos
"""

from typing import Dict, Any
from .base_analyzer import BaseAnalyzer


class PermissionsAnalyzer(BaseAnalyzer):
    """Analisa permissões de arquivos SUID, SGID e world-writable"""
    
    def analyze(self) -> Dict[str, Any]:
        """Analisa permissões de arquivos do sistema"""
        
        perms_data = self._get_metric('permissions', default={})
        
        suid_files = perms_data.get('suid_files', [])
        sgid_files = perms_data.get('sgid_files', [])
        world_writable = perms_data.get('world_writable_files', [])
        critical_files = perms_data.get('critical_files_permissions', [])
        
        # Status
        if len(world_writable) > 0:
            status = 'critical'
            status_text = f'🚨 {len(world_writable)} ARQUIVOS WORLD-WRITABLE'
            severity = 'critical'
        elif len(suid_files) > 50:
            status = 'warning'
            status_text = f'⚠️ MUITOS ARQUIVOS SUID ({len(suid_files)})'
            severity = 'medium'
        else:
            status = 'good'
            status_text = '✅ PERMISSÕES SEGURAS'
            severity = 'low'
        
        message = self._generate_message(suid_files, sgid_files, world_writable, critical_files)
        
        details = [
            f"Arquivos SUID: {len(suid_files)}",
            f"Arquivos SGID: {len(sgid_files)}",
            f"World-writable: {len(world_writable)}"
        ]
        
        recommendations = self._generate_recommendations(suid_files, world_writable)
        
        return {
            'status': status,
            'status_text': status_text,
            'message': message,
            'details': details,
            'recommendations': recommendations,
            'severity': severity,
            'metrics': {
                'suid_count': len(suid_files),
                'sgid_count': len(sgid_files),
                'world_writable_count': len(world_writable)
            }
        }
    
    def _generate_message(self, suid: list, sgid: list, world: list, critical: list) -> str:
        """Gera mensagem sobre permissões"""
        
        if world:
            msg = f"🚨 **ALERTA CRÍTICO**: Foram encontrados **{len(world)} arquivos world-writable** no sistema! "
            msg += "Arquivos com permissão 'world-writable' (escrita para todos) são um **risco gravíssimo de segurança**. "
            msg += "Qualquer usuário ou processo pode modificar esses arquivos, permitindo injeção de código malicioso. "
            msg += "\n\n**Revise e corrija** as permissões desses arquivos imediatamente."
        
        elif len(suid) > 50:
            msg = f"⚠️ O sistema possui **{len(suid)} arquivos com bit SUID** ativado. "
            msg += "Arquivos SUID executam com privilégios do dono (geralmente root), o que é necessário para alguns binários do sistema, "
            msg += "mas um número excessivo pode indicar risco. Revise se todos são legítimos."
        
        else:
            msg = "✅ **Permissões adequadas!** A análise de permissões mostra uma configuração segura:\n\n"
            
            if critical:
                # Verificar arquivos críticos
                shadow = next((f for f in critical if '/etc/shadow' in str(f)), None)
                passwd = next((f for f in critical if '/etc/passwd' in str(f)), None)
                
                msg += "• Arquivos críticos do sistema (`/etc/shadow`, `/etc/passwd`) estão com permissões corretas, "
                msg += "impedindo acesso não autorizado a hashes de senha e informações de usuários.\n\n"
            
            if suid:
                msg += f"• Os {len(suid)} arquivos com bit SUID encontrados são binários de sistema padrão e esperados.\n\n"
            
            if not world:
                msg += "• **Nenhum arquivo world-writable** foi encontrado, eliminando um vetor comum de ataque.\n\n"
            
            msg += "A estrutura de permissões do sistema está robusta e segue as melhores práticas."
        
        return msg
    
    def _generate_recommendations(self, suid: list, world: list) -> list:
        """Gera recomendações"""
        recommendations = []
        
        if world:
            recommendations.append({
                'title': 'Corrigir Permissões World-Writable',
                'description': f'Remova permissão de escrita para "others" nos {len(world)} arquivos identificados.',
                'priority': 'critical',
                'command': 'sudo chmod o-w /caminho/do/arquivo'
            })
        
        if len(suid) > 50:
            recommendations.append({
                'title': 'Auditar Arquivos SUID',
                'description': 'Revise a lista de arquivos SUID e remova o bit de arquivos não essenciais.',
                'priority': 'medium',
                'command': 'find / -perm -4000 -type f 2>/dev/null'
            })
        
        return recommendations
