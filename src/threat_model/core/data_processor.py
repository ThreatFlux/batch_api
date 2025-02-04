"""Data processing and correlation logic for threat model generation."""
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .config import CSV_SETTINGS, CORRELATION_WEIGHTS

logger = logging.getLogger(__name__)

class DataProcessor:
    """Handles data processing and correlation for threat modeling."""
    
    def __init__(self):
        """Initialize the data processor."""
        self.mitre_data: pd.DataFrame = pd.DataFrame()
        self.idp_data: pd.DataFrame = pd.DataFrame()
        self.audit_data: pd.DataFrame = pd.DataFrame()
        self.correlation_matrix: Dict[str, List[Tuple[str, float]]] = {}
        self.vectorizer = TfidfVectorizer(stop_words='english')
        
    def load_csv(self, file_path: Path, file_type: str) -> None:
        """Load and validate a CSV file.
        
        Args:
            file_path: Path to the CSV file
            file_type: Type of file ('mitre' or 'audit')
        """
        try:
            settings = CSV_SETTINGS[file_type]
            df = pd.read_csv(
                file_path,
                encoding=settings['encoding'],
                on_bad_lines='warn'
            )
            
            # Validate required columns
            missing_cols = set(settings['required_columns']) - set(df.columns)
            if missing_cols:
                raise ValueError(f"Missing required columns: {missing_cols}")
                
            # Clean and preprocess
            df = self._preprocess_dataframe(df)
            # Store the data in the appropriate attribute
            if file_type == 'mitre':
                self.mitre_data = df
            elif file_type == 'idp':
                self.idp_data = df
            else:
                self.audit_data = df
                self.audit_data = df
                
            logger.info(f"Successfully loaded {file_type} data from {file_path}")
            
        except Exception as e:
            logger.error(f"Error loading {file_type} data: {str(e)}")
            raise
            
    def _preprocess_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and preprocess a DataFrame.
        
        Args:
            df: Input DataFrame
            
        Returns:
            Preprocessed DataFrame
        """
        # Handle missing values
        df = df.fillna('')
        
        # Clean text fields
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].str.strip()
                
        # Remove duplicate entries
        df = df.drop_duplicates()
        
        return df
        
    def correlate_techniques_with_operations(self) -> Dict[str, List[Tuple[str, float]]]:
        """Correlate MITRE techniques with audit operations.
        
        Returns:
            Dictionary mapping technique IDs to lists of (operation, score) tuples
        """
        if self.mitre_data.empty or self.audit_data.empty:
            raise ValueError("Data must be loaded before correlation")
            
        correlation_matrix: Dict[str, List[Tuple[str, float]]] = {}
        
        # Prepare text for similarity comparison
        mitre_descriptions = self.mitre_data['Description'].tolist()
        audit_descriptions = self.audit_data['Description'].tolist()
        
        # Calculate TF-IDF and similarity scores
        try:
            tfidf_matrix = self.vectorizer.fit_transform(mitre_descriptions + audit_descriptions)
            similarity_matrix = cosine_similarity(
                tfidf_matrix[:len(mitre_descriptions)],
                tfidf_matrix[len(mitre_descriptions):]
            )
        except Exception as e:
            logger.error(f"Error calculating similarity scores: {str(e)}")
            raise
            
        # Calculate correlations
        for i, row in self.mitre_data.iterrows():
            technique_id = row['TID']
            correlations: List[Tuple[str, float]] = []
            
            for j, op_row in self.audit_data.iterrows():
                score = self._calculate_correlation_score(
                    row,
                    op_row,
                    similarity_matrix[i][j]
                )
                
                if score > 0:
                    correlations.append((op_row['Operation'], score))
                    
            # Sort by score and keep top correlations
            correlations.sort(key=lambda x: x[1], reverse=True)
            correlation_matrix[technique_id] = correlations[:10]  # Keep top 10
            
        self.correlation_matrix = correlation_matrix
        return correlation_matrix
        
    def _calculate_correlation_score(
        self,
        technique: pd.Series,
        operation: pd.Series,
        similarity_score: float
    ) -> float:
        """Calculate correlation score between a technique and operation.
        
        Args:
            technique: MITRE technique data
            operation: Audit operation data
            similarity_score: TF-IDF similarity score
            
        Returns:
            Correlation score between 0 and 1
        """
        score = 0.0
        
        # Check for exact matches in operation names
        if str(technique['Technique']).lower() in str(operation['Operation']).lower():
            score += CORRELATION_WEIGHTS['exact_match']
            
        # Check for partial matches
        if any(word.lower() in str(operation['Operation']).lower() 
               for word in str(technique['Technique']).split()):
            score += CORRELATION_WEIGHTS['partial_match']
            
        # Add weighted similarity score
        score += similarity_score * CORRELATION_WEIGHTS['description_similarity']
        
        return min(score, 1.0)  # Cap at 1.0
        
    def get_related_techniques(self, technique_id: str) -> List[Tuple[str, float]]:
        """Find related techniques based on shared operations.
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            List of (technique_id, similarity_score) tuples
        """
        if not self.correlation_matrix or technique_id not in self.correlation_matrix:
            return []
            
        # Get operations correlated with this technique
        technique_ops = set(op for op, _ in self.correlation_matrix[technique_id])
        
        related: List[Tuple[str, float]] = []
        for other_id, other_correlations in self.correlation_matrix.items():
            if other_id == technique_id:
                continue
                
            # Get operations correlated with other technique
            other_ops = set(op for op, _ in other_correlations)
            
            # Calculate Jaccard similarity of operation sets
            intersection = len(technique_ops & other_ops)
            union = len(technique_ops | other_ops)
            
            if union > 0:
                similarity = intersection / union
                if similarity > 0.1:  # Minimum similarity threshold
                    related.append((other_id, similarity))
                    
        return sorted(related, key=lambda x: x[1], reverse=True)
        
    def get_technique_groups(self) -> List[List[str]]:
        """Group related techniques based on shared operations.
        
        Returns:
            List of technique ID groups
        """
        if not self.correlation_matrix:
            return []
            
        groups: List[List[str]] = []
        processed: set = set()
        
        for technique_id in self.correlation_matrix:
            if technique_id in processed:
                continue
                
            # Start a new group
            group: set = {technique_id}
            related = self.get_related_techniques(technique_id)
            
            # Add highly related techniques to group
            for related_id, similarity in related:
                if similarity > 0.3 and related_id not in processed:  # Similarity threshold
                    group.add(related_id)
                    
            groups.append(list(group))
            processed.update(group)
            
        return groups