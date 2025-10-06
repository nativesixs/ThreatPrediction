"""
Autoencoder model for anomaly detection.
Trained only on normal traffic to learn reconstruction of typical flows.
"""
import torch
import torch.nn as nn


class Autoencoder(nn.Module):
    """
    Deep autoencoder for network flow anomaly detection.
    
    Architecture:
    - Encoder: progressively smaller layers compress input to latent space
    - Decoder: mirrors encoder to reconstruct input
    - Trained on normal traffic only using MSE loss
    - Anomalies produce high reconstruction error
    """
    
    def __init__(self, input_size: int, hidden_layers: list = None):
        """
        Initialize autoencoder.
        
        Args:
            input_size: Number of input features
            hidden_layers: List of hidden layer sizes for encoder
                          (default: [128, 64, 32, 16])
        """
        super(Autoencoder, self).__init__()
        
        if hidden_layers is None:
            hidden_layers = [128, 64, 32, 16]
        
        self.input_size = input_size
        self.hidden_layers = hidden_layers
        
        # Build encoder
        encoder_layers = []
        prev_size = input_size
        for hidden_size in hidden_layers:
            encoder_layers.append(nn.Linear(prev_size, hidden_size))
            encoder_layers.append(nn.ReLU())
            prev_size = hidden_size
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Build decoder (mirror of encoder)
        decoder_layers = []
        reversed_layers = list(reversed(hidden_layers[:-1])) + [input_size]
        prev_size = hidden_layers[-1]  # Start from bottleneck
        for hidden_size in reversed_layers:
            decoder_layers.append(nn.Linear(prev_size, hidden_size))
            if hidden_size != input_size:  # No activation on output layer
                decoder_layers.append(nn.ReLU())
            prev_size = hidden_size
        self.decoder = nn.Sequential(*decoder_layers)
    
    def forward(self, x):
        """
        Forward pass through autoencoder.
        
        Args:
            x: Input tensor of shape (batch_size, input_size)
        
        Returns:
            Reconstructed input tensor
        """
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed
    
    def encode(self, x):
        """Get latent representation."""
        return self.encoder(x)
    
    def decode(self, latent):
        """Reconstruct from latent representation."""
        return self.decoder(latent)
    
    def get_architecture(self):
        """Return architecture description."""
        return {
            'input_size': self.input_size,
            'encoder_layers': self.hidden_layers,
            'decoder_layers': list(reversed(self.hidden_layers[:-1])) + [self.input_size],
            'bottleneck_size': self.hidden_layers[-1]
        }
