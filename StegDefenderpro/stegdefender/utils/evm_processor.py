import cv2
import numpy as np
import scipy.fftpack as fftpack
import scipy.signal as signal
import os

class EVMProcessor:
    """
    Eulerian Video Magnification (EVM) Processor.
    Used to amplify subtle color/temporal changes in video that might be 
    indicative of high-frequency steganographic pulsing.
    """
    
    @staticmethod
    def amplify_video(video_path, output_path, low=0.4, high=3.0, amp=50):
        """
        Processes a video and creates a magnified version highlighting temporal changes.
        """
        cap = cv2.VideoCapture(video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        if fps == 0: fps = 30
        
        frames = []
        count = 0
        # Limit frames for performance (analyze 2-3 seconds)
        max_frames = int(fps * 3) 
        
        while cap.isOpened() and count < max_frames:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
            count += 1
        cap.release()

        if len(frames) < 10:
            return False

        # 1. Convert to float and downsample (Gaussian Pyramid Level 2-3 for speed)
        # We work on a smaller scale because stego pulsing is often global or regional
        video_tensor = np.array(frames).astype(np.float32)
        
        # 2. Temporal Bandpass Filter
        # We want to isolate frequencies between 'low' and 'high' Hz
        # (e.g., 0.4Hz to 3Hz covers human pulse and common electronic flickering)
        filtered_tensor = EVMProcessor._temporal_bandpass_filter(video_tensor, fps, low, high)
        
        # 3. Amplify
        magnified_tensor = filtered_tensor * amp
        
        # 4. Add back to original
        final_video = video_tensor + magnified_tensor
        
        # 5. Normalize and Save as a sequence or GIF/MP4
        # For our forensic tool, we'll save a "Heatmap" frame and an animated result
        EVMProcessor._save_as_video(final_video, output_path, fps)
        
        # Also return a "Temporal Variance" map (Static image showing where most change happened)
        variance_map = np.var(filtered_tensor, axis=0)
        variance_map = cv2.normalize(variance_map, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
        heatmap_path = output_path.replace('.mp4', '_heatmap.png')
        cv2.imwrite(heatmap_path, cv2.applyColorMap(variance_map, cv2.COLORMAP_JET))
        
        return heatmap_path

    @staticmethod
    def _temporal_bandpass_filter(tensor, fps, low, high):
        """
        Applies a Butterworth bandpass filter along the time axis.
        """
        # FFT along the time axis (axis 0)
        fft = fftpack.fft(tensor, axis=0)
        frequencies = fftpack.fftfreq(tensor.shape[0], d=1.0/fps)
        
        # Create mask
        mask = (frequencies >= low) & (frequencies <= high)
        
        # Zero out frequencies outside the band
        fft[~mask] = 0
        
        # Inverse FFT
        return np.real(fftpack.ifft(fft, axis=0))

    @staticmethod
    def _save_as_video(tensor, output_path, fps):
        """
        Saves the processed tensor back to a video file.
        """
        # Clip and convert back to uint8
        tensor = np.clip(tensor, 0, 255).astype(np.uint8)
        height, width = tensor.shape[1:3]
        
        # Use MJPG for compatibility and low overhead
        fourcc = cv2.VideoWriter_fourcc(*'avc1')
        if os.name == 'nt': # Windows fallback
             fourcc = cv2.VideoWriter_fourcc(*'mp4v')
             
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        for i in range(tensor.shape[0]):
            out.write(tensor[i])
        out.release()
