import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { axiosInstance } from '../Config';


export const fetchUsers = createAsyncThunk('users/fetchUsers', async () => {
  const response = await axiosInstance.get('/user_list');
  return response.data.body.data; 
});

export const deleteUser = createAsyncThunk('users/deleteUser', async (_id) => {
  await axiosInstance.delete(`/user_delete/${_id}`);
  return _id; 
});

export const toggleUserStatus = createAsyncThunk(
  'users/toggleUserStatus',
  async ({ id, currentStatus }) => {
    const newStatus = currentStatus === '0' ? '1' : '0';
    const response = await axiosInstance.post('/userstatus', { id, status: newStatus });
    return { id, newStatus: response.data.success ? newStatus : currentStatus };
  }
);

const userSlice = createSlice({
  name: 'users',
  initialState: {
    users: [],
    error: null,
    loading: false,
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchUsers.pending, (state) => {
        state.loading = true;
      })
      .addCase(fetchUsers.fulfilled, (state, action) => {
        state.loading = false;
        state.users = action.payload;
      })
      .addCase(fetchUsers.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      .addCase(deleteUser.fulfilled, (state, action) => {
        state.users = state.users.filter((user) => user._id !== action.payload);
      })
      .addCase(toggleUserStatus.fulfilled, (state, action) => {
        const { id, newStatus } = action.payload;
        const userIndex = state.users.findIndex((user) => user._id === id);
        if (userIndex >= 0) {
          state.users[userIndex].status = newStatus;
        }
      });
  },
});

export default userSlice.reducer;
