"""
Email Attachment Malware Analysis Module
Extends phishing detection with attachment threat analysis
"""

import hashlib
import mimetypes
import math
from pathlib import Path
from typing import Dict, List, Tuple
import zipfile
import io
import re


class AttachmentAnalyzer:
    """
    Analyzes email attachments for malware indicators without execution
    """
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
        '.js', '.jar', '.ps1', '.msi', '.hta', '.wsf', '.reg'
    }
    
    # Document extensions that can contain macros
    MACRO_CAPABLE = {
        '.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppsm'
    }
    
    # Archive extensions
    ARCHIVE_EXTENSIONS = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
    }
    
    def __init__(self):
        self.analysis_results = {}
    
    def analyze_attachment(self, file_bytes: bytes, filename: str) -> Dict:
        """
        Main analysis function for a single attachment
        
        Args:
            file_bytes: Raw bytes of the file
            filename: Original filename
            
        Returns:
            Dictionary containing all analysis results
        """
        results = {
            'filename': filename,
            'size': len(file_bytes),
            'metadata': self._extract_metadata(file_bytes, filename),
            'hash': self._calculate_hash(file_bytes),
            'static_analysis': self._static_analysis(file_bytes, filename),
            'risk_indicators': [],
            'risk_score': 0,
            'classification': 'Unknown'
        }
        
        # Perform detailed analysis
        results['risk_indicators'] = self._identify_risk_indicators(results)
        results['risk_score'] = self._calculate_risk_score(results)
        results['classification'] = self._classify_attachment(results['risk_score'])
        
        return results
    
    def _extract_metadata(self, file_bytes: bytes, filename: str) -> Dict:
        """Extract file metadata"""
        extension = Path(filename).suffix.lower()
        mime_type, _ = mimetypes.guess_type(filename)
        
        return {
            'extension': extension,
            'mime_type': mime_type or 'unknown',
            'size_mb': round(len(file_bytes) / (1024 * 1024), 2)
        }
    
    def _calculate_hash(self, file_bytes: bytes) -> str:
        """Calculate SHA-256 hash"""
        return hashlib.sha256(file_bytes).hexdigest()
    
    def _static_analysis(self, file_bytes: bytes, filename: str) -> Dict:
        """Perform static analysis without execution"""
        analysis = {
            'entropy': self._calculate_entropy(file_bytes),
            'extension_mismatch': self._check_extension_mismatch(filename),
            'macro_detected': self._check_macros(file_bytes, filename),
            'embedded_script': self._check_embedded_scripts(file_bytes, filename),
            'double_archive': self._check_double_archive(file_bytes, filename),
            'suspicious_patterns': self._check_suspicious_patterns(file_bytes, filename)
        }
        
        return analysis
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy to detect obfuscation/encryption
        High entropy (>7.0) suggests compression or encryption
        """
        if not data:
            return 0.0
        
        # Use first 10KB for performance
        sample = data[:10240]
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in sample:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(sample)
        
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
    
    def _check_extension_mismatch(self, filename: str) -> bool:
        """
        Detect extension mismatches like .pdf.exe
        Returns True if suspicious
        """
        # Check for double extensions
        name_parts = filename.split('.')
        if len(name_parts) >= 3:
            # Check if second-to-last part looks like an extension
            potential_ext = '.' + name_parts[-2].lower()
            actual_ext = '.' + name_parts[-1].lower()
            
            # If second-to-last looks like extension and last is executable
            if potential_ext in ['.pdf', '.doc', '.jpg', '.png', '.txt'] and \
               actual_ext in self.DANGEROUS_EXTENSIONS:
                return True
        
        return False
    
    def _check_macros(self, file_bytes: bytes, filename: str) -> bool:
        """
        Check for macros in Office documents
        Returns True if macros detected
        """
        extension = Path(filename).suffix.lower()
        
        # Macro-enabled Office formats
        if extension in self.MACRO_CAPABLE:
            return True
        
        # Check for VBA signatures in content
        try:
            content = file_bytes[:10240].decode('utf-8', errors='ignore').lower()
            if 'vba' in content or 'macros' in content or 'activex' in content:
                return True
        except:
            pass
        
        # Check binary markers for Office files
        if file_bytes[:4] == b'PK\x03\x04':  # ZIP format (modern Office)
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    for name in zf.namelist():
                        if 'vba' in name.lower() or 'macro' in name.lower():
                            return True
            except:
                pass
        
        return False
    
    def _check_embedded_scripts(self, file_bytes: bytes, filename: str) -> bool:
        """
        Detect embedded scripts in PDFs, HTML, etc.
        Returns True if scripts found
        """
        extension = Path(filename).suffix.lower()
        
        try:
            # Sample first 50KB
            sample = file_bytes[:51200].decode('utf-8', errors='ignore').lower()
            
            # Check for script tags
            script_patterns = [
                r'<script',
                r'javascript:',
                r'eval\(',
                r'document\.write',
                r'/js\s',
                r'vbscript',
                r'powershell',
                r'cmd\.exe'
            ]
            
            for pattern in script_patterns:
                if re.search(pattern, sample):
                    return True
            
            # PDF specific checks
            if extension == '.pdf' and (b'/JavaScript' in file_bytes[:10240] or 
                                        b'/JS' in file_bytes[:10240]):
                return True
        
        except:
            pass
        
        return False
    
    def _check_double_archive(self, file_bytes: bytes, filename: str) -> bool:
        """
        Check for nested archives (ZIP in ZIP)
        Returns True if double archive detected
        """
        extension = Path(filename).suffix.lower()
        
        if extension not in self.ARCHIVE_EXTENSIONS:
            return False
        
        try:
            if extension == '.zip':
                with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                    for name in zf.namelist():
                        inner_ext = Path(name).suffix.lower()
                        if inner_ext in self.ARCHIVE_EXTENSIONS:
                            return True
        except:
            pass
        
        return False
    
    def _check_suspicious_patterns(self, file_bytes: bytes, filename: str) -> List[str]:
        """
        Check for suspicious patterns in filename and content
        """
        patterns = []
        
        # Filename patterns
        filename_lower = filename.lower()
        suspicious_words = ['invoice', 'payment', 'urgent', 'account', 'verify', 
                          'confirm', 'security', 'update', 'refund', 'banking']
        
        for word in suspicious_words:
            if word in filename_lower:
                patterns.append(f"Suspicious filename keyword: {word}")
        
        # Check for spaces in extension (obfuscation)
        if '  ' in filename or '\t' in filename:
            patterns.append("Multiple spaces in filename (obfuscation)")
        
        # Check for unicode tricks
        if any(ord(c) > 127 for c in filename):
            patterns.append("Unicode characters in filename")
        
        return patterns
    
    def _identify_risk_indicators(self, results: Dict) -> List[str]:
        """
        Compile list of risk indicators from analysis
        """
        indicators = []
        
        metadata = results['metadata']
        static = results['static_analysis']
        
        # Extension-based indicators
        if metadata['extension'] in self.DANGEROUS_EXTENSIONS:
            indicators.append(f"Dangerous file extension: {metadata['extension']}")
        
        if metadata['extension'] in self.MACRO_CAPABLE:
            indicators.append(f"Macro-capable document: {metadata['extension']}")
        
        # Static analysis indicators
        if static['entropy'] > 7.0:
            indicators.append(f"High entropy ({static['entropy']}) - possible encryption/obfuscation")
        
        if static['extension_mismatch']:
            indicators.append("Extension mismatch detected (e.g., .pdf.exe)")
        
        if static['macro_detected']:
            indicators.append("Macros detected in document")
        
        if static['embedded_script']:
            indicators.append("Embedded scripts detected")
        
        if static['double_archive']:
            indicators.append("Nested archive detected (ZIP in ZIP)")
        
        # Add suspicious patterns
        indicators.extend(static['suspicious_patterns'])
        
        # Size-based indicators
        if metadata['size_mb'] > 50:
            indicators.append(f"Unusually large file size: {metadata['size_mb']} MB")
        elif metadata['size_mb'] < 0.001 and metadata['extension'] not in ['.txt']:
            indicators.append("Suspiciously small file size")
        
        return indicators
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """
        Calculate risk score (0-100) based on indicators
        """
        score = 0
        
        metadata = results['metadata']
        static = results['static_analysis']
        indicators = results['risk_indicators']
        
        # Dangerous extensions: +40
        if metadata['extension'] in self.DANGEROUS_EXTENSIONS:
            score += 40
        
        # Extension mismatch: +30
        if static['extension_mismatch']:
            score += 30
        
        # Macros: +25
        if static['macro_detected']:
            score += 25
        
        # Embedded scripts: +25
        if static['embedded_script']:
            score += 25
        
        # High entropy: +20
        if static['entropy'] > 7.5:
            score += 20
        elif static['entropy'] > 7.0:
            score += 10
        
        # Double archive: +15
        if static['double_archive']:
            score += 15
        
        # Suspicious patterns: +5 each (max 20)
        pattern_score = min(len(static['suspicious_patterns']) * 5, 20)
        score += pattern_score
        
        # Cap at 100
        return min(score, 100)
    
    def _classify_attachment(self, risk_score: int) -> str:
        """
        Classify attachment based on risk score
        """
        if risk_score >= 70:
            return "Malicious"
        elif risk_score >= 40:
            return "Suspicious"
        else:
            return "Safe"
    
    def generate_explanation(self, results: Dict) -> str:
        """
        Generate human-readable explanation
        """
        classification = results['classification']
        score = results['risk_score']
        indicators = results['risk_indicators']
        
        explanation = f"**Attachment Classification: {classification}**\n"
        explanation += f"**Risk Score: {score}/100**\n\n"
        
        if not indicators:
            explanation += "No significant risk indicators detected. The file appears to be safe based on static analysis.\n"
        else:
            explanation += "**Risk Indicators Detected:**\n"
            for indicator in indicators:
                explanation += f"• {indicator}\n"
        
        explanation += f"\n**File Hash (SHA-256):** `{results['hash']}`\n"
        explanation += f"**File Size:** {results['metadata']['size_mb']} MB\n"
        explanation += f"**Entropy:** {results['static_analysis']['entropy']}/8.0\n"
        
        return explanation


def correlate_risks(email_risk_score: int, attachment_results: List[Dict]) -> Dict:
    """
    Correlate email phishing score with attachment risk scores
    
    Args:
        email_risk_score: Risk score from email content analysis (0-100)
        attachment_results: List of attachment analysis results
        
    Returns:
        Dictionary with unified threat assessment
    """
    if not attachment_results:
        return {
            'unified_threat_score': email_risk_score,
            'overall_classification': classify_unified_threat(email_risk_score),
            'threat_correlation': 'No attachments to correlate'
        }
    
    # Calculate average attachment risk
    avg_attachment_risk = sum(r['risk_score'] for r in attachment_results) / len(attachment_results)
    max_attachment_risk = max(r['risk_score'] for r in attachment_results)
    
    # Unified scoring logic
    # If both email and attachments are high risk, amplify the threat
    if email_risk_score >= 70 and max_attachment_risk >= 70:
        unified_score = min(email_risk_score + 15, 100)
        correlation = "CRITICAL: Both email content and attachments show high-risk indicators"
    
    # If either is high risk
    elif email_risk_score >= 70 or max_attachment_risk >= 70:
        unified_score = max(email_risk_score, max_attachment_risk) + 5
        correlation = "HIGH: Either email content or attachments indicate significant threat"
    
    # Both moderate
    elif email_risk_score >= 40 and avg_attachment_risk >= 40:
        unified_score = int((email_risk_score + avg_attachment_risk) / 1.5)
        correlation = "MODERATE: Both email and attachments show suspicious indicators"
    
    # One is risky, other is safe
    elif (email_risk_score >= 40 and avg_attachment_risk < 40) or \
         (email_risk_score < 40 and avg_attachment_risk >= 40):
        unified_score = int((email_risk_score + max_attachment_risk) / 1.8)
        correlation = "MIXED: Discrepancy between email and attachment risk levels"
    
    # Both appear safe
    else:
        unified_score = int((email_risk_score + avg_attachment_risk) / 2)
        correlation = "LOW: Both email and attachments appear relatively safe"
    
    return {
        'unified_threat_score': min(unified_score, 100),
        'overall_classification': classify_unified_threat(unified_score),
        'threat_correlation': correlation,
        'email_risk': email_risk_score,
        'attachment_avg_risk': int(avg_attachment_risk),
        'attachment_max_risk': max_attachment_risk,
        'attachment_count': len(attachment_results)
    }


def classify_unified_threat(score: int) -> str:
    """Classify unified threat level"""
    if score >= 80:
        return "CRITICAL THREAT"
    elif score >= 70:
        return "HIGH THREAT"
    elif score >= 50:
        return "MODERATE THREAT"
    elif score >= 30:
        return "LOW THREAT"
    else:
        return "MINIMAL THREAT"
