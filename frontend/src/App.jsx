import React from 'react';
import { StreamChat } from 'stream-chat';
import { Chat } from 'stream-chat-react';
//import Cookies from 'universal-cookie';

import { ChannelListContainer, ChannelContainer } from './components';

import './App.css';

const apiKey = 'jnhrsgfa94vc';
const client = StreamChat.getInstance(apiKey);

const App = () => {
    return (
        <div className="app__wrapper">
            <Chat client={client} theme="team light">
                <ChannelListContainers
                
                />
                <ChannelContainer 
                
                />
            </Chat>
        </div>
    );
}

export default App
